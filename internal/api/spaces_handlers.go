package api

import (
	"context"
	"net/http"
	"time"

	"gobackend/internal/services"

	"github.com/gin-gonic/gin"
)

// SpacesHandlers handles DigitalOcean Spaces related API requests
type SpacesHandlers struct {
	spacesService *services.SpacesService
}

// NewSpacesHandlers creates a new Spaces handlers instance
func NewSpacesHandlers(spacesService *services.SpacesService) *SpacesHandlers {
	return &SpacesHandlers{
		spacesService: spacesService,
	}
}

// UploadSpaces handles audio data uploads to DigitalOcean Spaces
// @Summary Upload audio data to DigitalOcean Spaces
// @Description Upload audio data to a specified directory within a DigitalOcean Space
// @Tags files
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "The audio file to be uploaded"
// @Param filename formData string true "The name of the file to be uploaded"
// @Param directory formData string true "The directory within the DigitalOcean Space where the file will be uploaded (recordings, profile_pics, dashboards)"
// @Param sub_directory formData string false "The subdirectory within the specified directory where the file will be uploaded"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/upload-spaces [post]
func (h *SpacesHandlers) UploadSpaces(c *gin.Context) {
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

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	// Upload file asynchronously
	fileURL, err := h.spacesService.UploadFileAsync(ctx, file, filename, directory, subDirectory)
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

// SpacesHealth checks the health of the DigitalOcean Spaces connection
// @Summary Health check for DigitalOcean Spaces connection
// @Description Verify the connection to DigitalOcean Spaces by listing objects in the bucket
// @Tags health
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ResponseError
// @Router /api/v1/spaces-health [get]
func (h *SpacesHandlers) SpacesHealth(c *gin.Context) {
	if h.spacesService == nil {
		c.JSON(http.StatusInternalServerError, ResponseError{
			Error: "Spaces service not configured",
		})
		return
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// Check connection to DigitalOcean Spaces
	status, details, err := h.spacesService.CheckHealth(ctx)
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
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// UploadSpacesV2 handles file uploads to DigitalOcean Spaces
// @Summary Upload a file to DigitalOcean Spaces
// @Description Upload a file to a specified directory within a DigitalOcean Space
// @Tags files
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "The file to be uploaded"
// @Param filename formData string true "The name of the file to be uploaded"
// @Param directory formData string true "The directory within the DigitalOcean Space where the file will be uploaded (recordings, profile_pics, dashboards)"
// @Param sub_directory formData string false "The subdirectory within the specified directory where the file will be uploaded"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ResponseError
// @Failure 401 {object} ResponseError
// @Failure 500 {object} ResponseError
// @Router /api/v1/upload-spaces-v2 [post]
func (h *SpacesHandlers) UploadSpacesV2(c *gin.Context) {
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

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	// Upload file asynchronously
	fileURL, err := h.spacesService.UploadFileAsync(ctx, file, filename, directory, subDirectory)
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
