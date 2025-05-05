package api

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Define a test interface that matches the method we need
type spacesServicer interface {
	UploadFileAsync(ctx interface{}, file multipart.File, filename string, directory string, subDirectory string) (string, error)
	CheckHealth(ctx interface{}) (string, map[string]string, error)
}

// Mock SpacesService for testing
type mockSpacesService struct {
	mock.Mock
}

func (m *mockSpacesService) UploadFileAsync(ctx interface{}, file multipart.File, filename string, directory string, subDirectory string) (string, error) {
	args := m.Called(ctx, file, filename, directory, subDirectory)
	return args.String(0), args.Error(1)
}

func (m *mockSpacesService) CheckHealth(ctx interface{}) (string, map[string]string, error) {
	args := m.Called(ctx)
	// Cast the second return value to map[string]string
	var details map[string]string
	if args.Get(1) != nil {
		details = args.Get(1).(map[string]string)
	}
	return args.String(0), details, args.Error(2)
}

// Create a test handler struct that uses our interface instead of the concrete service
type testSpacesHandlers struct {
	service spacesServicer
}

// Implement the handler method with our interface
func (h *testSpacesHandlers) UploadSpacesV2(c *gin.Context) {
	// Get file from form
	file, fileHeader, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid file: " + err.Error(),
		})
		return
	}
	defer file.Close()

	// Get parameters from form
	filename := c.PostForm("filename")
	if filename == "" {
		// Use original filename if not provided
		filename = fileHeader.Filename
	}

	directory := c.PostForm("directory")
	if directory == "" {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Directory is required",
		})
		return
	}

	subDirectory := c.PostForm("sub_directory")

	// Upload file asynchronously
	fileURL, err := h.service.UploadFileAsync(c.Request.Context(), file, filename, directory, subDirectory)
	if err != nil {
		status := http.StatusInternalServerError
		if err.Error() == "invalid directory" {
			status = http.StatusBadRequest
		}
		c.JSON(status, ResponseError{
			Error: "Failed to upload file: " + err.Error(),
		})
		return
	}

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"message": "File uploaded successfully",
		"url":     fileURL,
	})
}

// Implement the SpacesHealth handler
func (h *testSpacesHandlers) SpacesHealth(c *gin.Context) {
	// Check connection to DigitalOcean Spaces
	status, details, err := h.service.CheckHealth(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, ResponseError{
			Error: "Failed to connect to DigitalOcean Spaces: " + err.Error(),
		})
		return
	}

	// Return status with details
	c.JSON(http.StatusOK, gin.H{
		"status":    status,
		"details":   details,
		"timestamp": c.GetString("request_time"), // For testing we use a fixed timestamp
	})
}

// Implement the UploadSpaces handler
func (h *testSpacesHandlers) UploadSpaces(c *gin.Context) {
	// Get file from form
	file, fileHeader, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Invalid file: " + err.Error(),
		})
		return
	}
	defer file.Close()

	// Get parameters from form
	filename := c.PostForm("filename")
	if filename == "" {
		// Use original filename if not provided
		filename = fileHeader.Filename
	}

	directory := c.PostForm("directory")
	if directory == "" {
		c.JSON(http.StatusBadRequest, ResponseError{
			Error: "Directory is required",
		})
		return
	}

	subDirectory := c.PostForm("sub_directory")

	// Upload file asynchronously
	fileURL, err := h.service.UploadFileAsync(c.Request.Context(), file, filename, directory, subDirectory)
	if err != nil {
		status := http.StatusInternalServerError
		if err.Error() == "invalid directory" {
			status = http.StatusBadRequest
		}
		c.JSON(status, ResponseError{
			Error: "Failed to upload file: " + err.Error(),
		})
		return
	}

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"message": "Audio file uploaded successfully",
		"url":     fileURL,
	})
}

func TestUploadSpacesV2(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		name           string
		fileContent    string
		filename       string
		directory      string
		subDirectory   string
		mockReturn     string
		mockError      error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Success - Valid upload",
			fileContent:    "test file content",
			filename:       "test.txt",
			directory:      "recordings",
			subDirectory:   "user123",
			mockReturn:     "https://cdn.example.com/recordings/user123/test-123.txt",
			mockError:      nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "File uploaded successfully",
		},
		{
			name:           "Failure - Invalid directory",
			fileContent:    "test file content",
			filename:       "test.txt",
			directory:      "invalid-dir",
			subDirectory:   "",
			mockReturn:     "",
			mockError:      errors.New("invalid directory"),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Failed to upload file: invalid directory",
		},
		{
			name:           "Failure - Upload error",
			fileContent:    "test file content",
			filename:       "test.txt",
			directory:      "recordings",
			subDirectory:   "",
			mockReturn:     "",
			mockError:      errors.New("upload failed"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Failed to upload file: upload failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a multipart form
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)

			// Add file part
			part, _ := writer.CreateFormFile("file", tc.filename)
			io.Copy(part, strings.NewReader(tc.fileContent))

			// Add form fields
			writer.WriteField("filename", tc.filename)
			writer.WriteField("directory", tc.directory)
			if tc.subDirectory != "" {
				writer.WriteField("sub_directory", tc.subDirectory)
			}
			writer.Close()

			// Create request and recorder
			req, _ := http.NewRequest("POST", "/api/v1/upload-spaces-v2", body)
			req.Header.Set("Content-Type", writer.FormDataContentType())
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Create mock service
			mockSvc := new(mockSpacesService)

			// Set up mock expectation - use Anything matcher for file since we can't easily compare it
			mockSvc.On("UploadFileAsync", mock.Anything, mock.Anything, tc.filename, tc.directory, tc.subDirectory).
				Return(tc.mockReturn, tc.mockError)

			// Create handler with mock
			handler := &testSpacesHandlers{
				service: mockSvc,
			}

			// Call handler
			handler.UploadSpacesV2(c)

			// Check response status
			assert.Equal(t, tc.expectedStatus, w.Code)

			// Check response body contains expected string
			assert.Contains(t, w.Body.String(), tc.expectedBody)

			// Check URL in response if success
			if tc.mockError == nil {
				assert.Contains(t, w.Body.String(), tc.mockReturn)
			}

			// Verify mock was called as expected
			mockSvc.AssertExpectations(t)
		})
	}
}

func TestUploadSpaces(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		name           string
		fileContent    string
		filename       string
		directory      string
		subDirectory   string
		mockReturn     string
		mockError      error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Success - Valid audio upload",
			fileContent:    "audio file content",
			filename:       "audio.mp3",
			directory:      "recordings",
			subDirectory:   "user123",
			mockReturn:     "https://cdn.example.com/recordings/user123/audio-123.mp3",
			mockError:      nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "Audio file uploaded successfully",
		},
		{
			name:           "Failure - Invalid directory",
			fileContent:    "audio file content",
			filename:       "audio.mp3",
			directory:      "invalid-dir",
			subDirectory:   "",
			mockReturn:     "",
			mockError:      errors.New("invalid directory"),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Failed to upload file: invalid directory",
		},
		{
			name:           "Failure - Upload error",
			fileContent:    "audio file content",
			filename:       "audio.mp3",
			directory:      "recordings",
			subDirectory:   "",
			mockReturn:     "",
			mockError:      errors.New("upload failed"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Failed to upload file: upload failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a multipart form
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)

			// Add file part
			part, _ := writer.CreateFormFile("file", tc.filename)
			io.Copy(part, strings.NewReader(tc.fileContent))

			// Add form fields
			writer.WriteField("filename", tc.filename)
			writer.WriteField("directory", tc.directory)
			if tc.subDirectory != "" {
				writer.WriteField("sub_directory", tc.subDirectory)
			}
			writer.Close()

			// Create request and recorder
			req, _ := http.NewRequest("POST", "/api/v1/upload-spaces", body)
			req.Header.Set("Content-Type", writer.FormDataContentType())
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Create mock service
			mockSvc := new(mockSpacesService)

			// Set up mock expectation - use Anything matcher for file since we can't easily compare it
			mockSvc.On("UploadFileAsync", mock.Anything, mock.Anything, tc.filename, tc.directory, tc.subDirectory).
				Return(tc.mockReturn, tc.mockError)

			// Create handler with mock
			handler := &testSpacesHandlers{
				service: mockSvc,
			}

			// Call handler
			handler.UploadSpaces(c)

			// Check response status
			assert.Equal(t, tc.expectedStatus, w.Code)

			// Check response body contains expected string
			assert.Contains(t, w.Body.String(), tc.expectedBody)

			// Check URL in response if success
			if tc.mockError == nil {
				assert.Contains(t, w.Body.String(), tc.mockReturn)
			}

			// Verify mock was called as expected
			mockSvc.AssertExpectations(t)
		})
	}
}

func TestSpacesHealth(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		name           string
		mockStatus     string
		mockDetails    map[string]string
		mockError      error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:       "Success - Healthy connection",
			mockStatus: "healthy",
			mockDetails: map[string]string{
				"bucket":   "test-bucket",
				"region":   "nyc3",
				"endpoint": "nyc3.digitaloceanspaces.com",
				"cdn_url":  "https://cdn.example.com",
			},
			mockError:      nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "healthy",
		},
		{
			name:       "Failure - Connection error",
			mockStatus: "failed",
			mockDetails: map[string]string{
				"error":    "connection refused",
				"bucket":   "test-bucket",
				"region":   "nyc3",
				"endpoint": "nyc3.digitaloceanspaces.com",
			},
			mockError:      errors.New("connection refused"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Failed to connect to DigitalOcean Spaces: connection refused",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request and recorder
			req, _ := http.NewRequest("GET", "/api/v1/spaces-health", nil)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Set("request_time", "2023-06-15T10:00:00Z") // Fixed timestamp for testing

			// Create mock service
			mockSvc := new(mockSpacesService)

			// Set up mock expectation
			mockSvc.On("CheckHealth", mock.Anything).
				Return(tc.mockStatus, tc.mockDetails, tc.mockError)

			// Create handler with mock
			handler := &testSpacesHandlers{
				service: mockSvc,
			}

			// Call handler
			handler.SpacesHealth(c)

			// Check response status
			assert.Equal(t, tc.expectedStatus, w.Code)

			// Check response body contains expected string
			assert.Contains(t, w.Body.String(), tc.expectedBody)

			// Check details in response if success
			if tc.mockError == nil {
				for _, v := range tc.mockDetails {
					assert.Contains(t, w.Body.String(), v)
				}
			}

			// Verify mock was called as expected
			mockSvc.AssertExpectations(t)
		})
	}
}

func TestUploadSpacesV2_MissingDirectory(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	// Create a multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add file part
	part, _ := writer.CreateFormFile("file", "test.txt")
	io.Copy(part, strings.NewReader("test content"))

	// Add filename but omit directory
	writer.WriteField("filename", "test.txt")
	writer.Close()

	// Create request and recorder
	req, _ := http.NewRequest("POST", "/api/v1/upload-spaces-v2", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Create mock service (should not be called)
	mockSvc := new(mockSpacesService)

	// Create handler with mock
	handler := &testSpacesHandlers{
		service: mockSvc,
	}

	// Call handler
	handler.UploadSpacesV2(c)

	// Check response
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Directory is required")

	// Verify mock was not called
	mockSvc.AssertNotCalled(t, "UploadFileAsync")
}

func TestUploadSpacesV2_MissingFile(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	// Create a multipart form without a file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add form fields but no file
	writer.WriteField("filename", "test.txt")
	writer.WriteField("directory", "recordings")
	writer.Close()

	// Create request and recorder
	req, _ := http.NewRequest("POST", "/api/v1/upload-spaces-v2", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Create mock service (should not be called)
	mockSvc := new(mockSpacesService)

	// Create handler with mock
	handler := &testSpacesHandlers{
		service: mockSvc,
	}

	// Call handler
	handler.UploadSpacesV2(c)

	// Check response
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid file")

	// Verify mock was not called
	mockSvc.AssertNotCalled(t, "UploadFileAsync")
}

func TestUploadSpaces_MissingDirectory(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	// Create a multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add file part
	part, _ := writer.CreateFormFile("file", "audio.mp3")
	io.Copy(part, strings.NewReader("audio content"))

	// Add filename but omit directory
	writer.WriteField("filename", "audio.mp3")
	writer.Close()

	// Create request and recorder
	req, _ := http.NewRequest("POST", "/api/v1/upload-spaces", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Create mock service (should not be called)
	mockSvc := new(mockSpacesService)

	// Create handler with mock
	handler := &testSpacesHandlers{
		service: mockSvc,
	}

	// Call handler
	handler.UploadSpaces(c)

	// Check response
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Directory is required")

	// Verify mock was not called
	mockSvc.AssertNotCalled(t, "UploadFileAsync")
}

func TestUploadSpaces_MissingFile(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	// Create a multipart form without a file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add form fields but no file
	writer.WriteField("filename", "audio.mp3")
	writer.WriteField("directory", "recordings")
	writer.Close()

	// Create request and recorder
	req, _ := http.NewRequest("POST", "/api/v1/upload-spaces", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Create mock service (should not be called)
	mockSvc := new(mockSpacesService)

	// Create handler with mock
	handler := &testSpacesHandlers{
		service: mockSvc,
	}

	// Call handler
	handler.UploadSpaces(c)

	// Check response
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid file")

	// Verify mock was not called
	mockSvc.AssertNotCalled(t, "UploadFileAsync")
}
