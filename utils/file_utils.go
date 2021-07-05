package utils

import (
	"fmt"
	"os"
)

// Exists returns whether the given file or directory exists
func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

// creates a folder if it doesn't exist
func CreateFolderIfNotExists(dataPath string) error {
	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		errMkDir := os.Mkdir(dataPath, 0777)
		if errMkDir != nil {
			fmt.Printf("Error creating directory: %s\n", err.Error())
			return fmt.Errorf("Error creating directory: %s", dataPath)
		}
	}
	return nil
}
