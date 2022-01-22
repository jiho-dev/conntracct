package kernel

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/sassoftware/go-rpmutils"
)

// curl downloads the given URL to the given filePath.
// No-ops if the file already exists.
func curl(url, filePath string) error {

	// Skip if destination path already exists.
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Printf("Downloading %s to %s..\n", url, filePath)

		if err := sh.Run("curl", "-s", "-L", url, "-o", filePath+".tmp"); err != nil {
			return err
		}

		if err := sh.Run("mv", filePath+".tmp", filePath); err != nil {
			return err
		}
	} else if mg.Verbose() {
		fmt.Println(filePath, "exists, skipping download.")
	}

	return nil
}

// unarchive extracts a gzip archive to a given directory.
// If path 'check' exists, the unarchive is skipped.
func unarchive(archive, dest, check string) error {

	// Skip if path already exists.
	if _, err := os.Stat(check); os.IsNotExist(err) {
		if mg.Verbose() {
			fmt.Printf("Extracting %s to %s..\n", archive, dest)
		}
		if err := sh.Run("tar", "xf", archive, "-C", dest); err != nil {
			return err
		}
		if mg.Verbose() {
			fmt.Printf("Extraction of %s complete!\n", archive)
		}
	} else if mg.Verbose() {
		fmt.Println(check, "exists, skipping unarchive.")
	}

	return nil
}

// trimExt removes .tar.gz and .tar.xz extensions from a string.
func trimExt(name string) string {

	name = strings.TrimSuffix(name, ".tar.gz")
	name = strings.TrimSuffix(name, ".tar.xz")
	name = strings.TrimSuffix(name, ".tar.bz2")
	name = strings.TrimSuffix(name, ".rpm")
	name = strings.TrimSuffix(name, ".deb")

	return name
}

func UnPackRPM(archive, archDest, kerDest, kerFile string) error {
	kname := path.Join(archDest, kerFile)

	/*
		fmt.Printf("### arch: %s \n", archive)
		fmt.Printf("### archdest: %s \n", archDest)
		fmt.Printf("### kerDest: %s \n", kerDest)
		fmt.Printf("### kernel: %s \n", kname)
	*/

	// Skip if path already exists.
	_, err := os.Stat(kerDest)
	if !os.IsNotExist(err) {
		fmt.Println(kerDest, "exists, skipping unarchive.")
		return nil
	}

	if mg.Verbose() {
		fmt.Printf("Extracting %s to %s..\n", archive, archDest)
	}

	// Opening a RPM file
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()

	rpm, err := rpmutils.ReadRpm(f)
	if err != nil {
		return err
	}

	// Extracting payload
	if err := rpm.ExpandPayload(archDest); err != nil {
		return err
	}

	if err := sh.Run("tar", "xf", kname, "-C", archDest); err != nil {
		return err
	}

	if mg.Verbose() {
		fmt.Printf("Extraction of %s complete!\n", kerDest)
	}

	return nil
}

func UnPackDebian(archive, archDest, kerDest, kerFile string) error {
	kname := path.Join(archDest, kerFile)

	/*
		fmt.Printf("### arch: %s \n", archive)
		fmt.Printf("### archdest: %s \n", archDest)
		fmt.Printf("### kerDest: %s \n", kerDest)
		fmt.Printf("### kernel: %s \n", kname)
	*/

	// Skip if path already exists.
	_, err := os.Stat(kerDest)
	if !os.IsNotExist(err) {
		fmt.Println(kerDest, "exists, skipping unarchive.")
		return nil
	}

	if mg.Verbose() {
		fmt.Printf("Extracting %s to %s..\n", archive, archDest)
	}

	if err := sh.Run("mkdir", "-p", archDest); err != nil {
		return err
	}

	cmd := exec.Command("ar", "-vx", archive)
	cmd.Dir = archDest
	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	fmt.Println(string(out))

	dataFile := path.Join(archDest, "data.tar.xz")
	cmd = exec.Command("tar", "xf", dataFile)
	cmd.Dir = archDest
	out, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}
	fmt.Println(string(out))

	c := path.Join(archDest, "usr/src", kerFile)
	if err := sh.Run("ln", "-s", c, kname); err != nil {
	}

	if err := sh.Run("tar", "xf", kname, "-C", archDest); err != nil {
		return err
	}

	if mg.Verbose() {
		fmt.Printf("Extraction of %s complete!\n", kerDest)
	}

	return nil
}
