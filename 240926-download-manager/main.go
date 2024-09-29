package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
)

type progressWriter struct {
	progressChan chan int64
}

func (w *progressWriter) Write(p []byte) (int, error) {
	w.progressChan <- int64(len(p))
	return len(p), nil
}

func main() {
	url := "https://github.com/XTLS/Xray-core/releases/download/v1.8.24/Xray-linux-64.zip"
	res, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching URL: ", err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		fmt.Println("Error downloading file: ", res.Status)
		return
	}

	file, err := os.Create("Xray-linux-64.zip")
	if err != nil {
		fmt.Println("Error crating file: ", err)
		return
	}
	defer file.Close()

	// Get the content length of the file
	contentLength, err := strconv.ParseInt(res.Header["Content-Length"][0], 10, 64)
	if err != nil {
		fmt.Println("Error getting content length: ", err)
		return
	}

	// Create a progress bar channel
	progressChan := make(chan int64)

	// Start a goroutine to update the progress bar
	go func() {
		var totalDownloaded int64
		for {
			select {
			case bytes := <-progressChan:
				totalDownloaded += bytes
				percent := float64(totalDownloaded) / float64(contentLength) * 100
				fmt.Printf("Progress: %.2f%% \r", percent)
			}
		}
	}()

	progressWriter := &progressWriter{progressChan: progressChan}

	// Copy the response body to the file, updating the progress bar
	_, err = io.Copy(file, io.TeeReader(res.Body, progressWriter))
	if err != nil {
		fmt.Println("Error writing file: ", err)
		return
	}

	fmt.Println("File downloaded successfully")
}
