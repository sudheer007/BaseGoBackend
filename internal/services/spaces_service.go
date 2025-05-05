package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/google/uuid"
)

// SpacesService provides functionality for uploading files to DigitalOcean Spaces
type SpacesService struct {
	s3Client *s3.S3
	bucket   string
	region   string
	cdnURL   string
}

// ValidDirectories contains the list of allowed upload directories
var ValidDirectories = []string{"recordings", "profile_pics", "dashboards"}

// SpacesConfig holds configuration for DigitalOcean Spaces
type SpacesConfig struct {
	AccessKey string
	SecretKey string
	Endpoint  string
	Region    string
	Bucket    string
	CDNURL    string
}

// NewSpacesService creates a new SpacesService with the given configuration
func NewSpacesService(cfg SpacesConfig) (*SpacesService, error) {
	// Create S3 session
	s3Config := &aws.Config{
		Credentials:      credentials.NewStaticCredentials(cfg.AccessKey, cfg.SecretKey, ""),
		Endpoint:         aws.String(cfg.Endpoint),
		Region:           aws.String(cfg.Region),
		S3ForcePathStyle: aws.Bool(true),
	}

	newSession, err := session.NewSession(s3Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	s3Client := s3.New(newSession)

	return &SpacesService{
		s3Client: s3Client,
		bucket:   cfg.Bucket,
		region:   cfg.Region,
		cdnURL:   cfg.CDNURL,
	}, nil
}

// CheckHealth verifies the connection to DigitalOcean Spaces
// It attempts to list objects in the bucket to confirm that credentials are valid
// and the service is accessible
func (s *SpacesService) CheckHealth(ctx context.Context) (string, map[string]string, error) {
	if s.s3Client == nil {
		return "failed", map[string]string{
			"error": "S3 client not initialized",
		}, errors.New("S3 client not initialized")
	}

	// Try to list objects with a limit of 1 to check connectivity
	input := &s3.ListObjectsV2Input{
		Bucket:  aws.String(s.bucket),
		MaxKeys: aws.Int64(1),
	}

	_, err := s.s3Client.ListObjectsV2WithContext(ctx, input)
	if err != nil {
		return "failed", map[string]string{
			"error":    err.Error(),
			"bucket":   s.bucket,
			"region":   s.region,
			"endpoint": *s.s3Client.Config.Endpoint,
		}, err
	}

	// Connection successful
	return "healthy", map[string]string{
		"bucket":   s.bucket,
		"region":   s.region,
		"endpoint": *s.s3Client.Config.Endpoint,
		"cdn_url":  s.cdnURL,
	}, nil
}

// UploadFileAsync uploads a file to DigitalOcean Spaces asynchronously
func (s *SpacesService) UploadFileAsync(ctx context.Context, file multipart.File, filename string, directory string, subDirectory string) (string, error) {
	// Validate directory
	if !isValidDirectory(directory) {
		return "", errors.New("invalid directory")
	}

	// Read the file content
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Generate unique filename to avoid overwrites
	uniqueFilename := generateUniqueFilename(filename)

	// Create the file path
	filePath := directory
	if subDirectory != "" {
		filePath = path.Join(filePath, subDirectory)
	}
	filePath = path.Join(filePath, uniqueFilename)

	// Start upload in a goroutine
	resultChan := make(chan struct {
		url string
		err error
	})

	go func() {
		// Upload the file to DigitalOcean Spaces
		_, uploadErr := s.s3Client.PutObject(&s3.PutObjectInput{
			Bucket:        aws.String(s.bucket),
			Key:           aws.String(filePath),
			ACL:           aws.String("public-read"),
			Body:          bytes.NewReader(fileBytes),
			ContentLength: aws.Int64(int64(len(fileBytes))),
			ContentType:   aws.String(detectContentType(filename)),
		})

		var fileURL string
		if uploadErr == nil {
			// Construct the URL for the uploaded file
			if s.cdnURL != "" {
				fileURL = fmt.Sprintf("%s/%s", strings.TrimRight(s.cdnURL, "/"), filePath)
			} else {
				fileURL = fmt.Sprintf("https://%s.%s.digitaloceanspaces.com/%s", s.bucket, s.region, filePath)
			}
		}

		resultChan <- struct {
			url string
			err error
		}{fileURL, uploadErr}
	}()

	// Wait for the result with context timeout
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-resultChan:
		if result.err != nil {
			return "", fmt.Errorf("failed to upload file: %w", result.err)
		}
		return result.url, nil
	}
}

// isValidDirectory checks if the directory is in the list of valid directories
func isValidDirectory(directory string) bool {
	for _, validDir := range ValidDirectories {
		if directory == validDir {
			return true
		}
	}
	return false
}

// generateUniqueFilename adds a UUID to the filename to make it unique
func generateUniqueFilename(filename string) string {
	ext := path.Ext(filename)
	basename := strings.TrimSuffix(filename, ext)
	uuid := uuid.New().String()
	return fmt.Sprintf("%s-%s%s", basename, uuid, ext)
}

// detectContentType attempts to determine the content type based on the file extension
func detectContentType(filename string) string {
	ext := strings.ToLower(path.Ext(filename))
	switch ext {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".pdf":
		return "application/pdf"
	case ".txt":
		return "text/plain"
	case ".html", ".htm":
		return "text/html"
	case ".json":
		return "application/json"
	case ".mp3":
		return "audio/mpeg"
	case ".mp4":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	default:
		return "application/octet-stream"
	}
}
