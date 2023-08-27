package maxm

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/3JoB/ulib/fsutil"
	"github.com/3JoB/unsafeConvert"
	"github.com/klauspost/compress/gzip"
	"github.com/valyala/fasthttp"
)

type Maxm struct {
	loc string
}

// Get retrieves all the teler threat datasets.
//
// It returns an error if there was an issue when retrieving the datasets.
func (x *Maxm) Get() error {
	// Delete existing threat datasets
	if err := os.RemoveAll(x.loc); err != nil {
		// If there was an error deleting the datasets, return the error
		return err
	}

	// Create the destination directory if it doesn't exist
	if err := os.MkdirAll(x.loc, 0755); err != nil {
		// If there was an error creating the directory, return the error
		return err
	}

	if err := x.get(ASNURL, asn_key, true); err != nil {
		return err
	}
	if err := x.get(CityURL, city_key, false); err != nil {
		return err
	}
	if err := x.get(CountryURL, country_key, false); err != nil {
		return err
	}
	// Return a nil error
	return nil
}

// Return ASN, City, Country
func (x *Maxm) GetName() (string, string, string) {
	return filepath.Join(x.loc, "/"+asn_key), filepath.Join(x.loc, "/"+city_key), filepath.Join(x.loc, "/"+country_key)
}

// location returns the location of the teler cache directory.
// It returns an error if there was an issue when getting the user cache directory.
func (x *Maxm) location() error {
	// Get the user cache directory using the os.UserCacheDir function
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		// If there was an error getting the user cache directory, return an empty string and the error
		return err
	}

	// Return the full path to the teler cache directory by joining the user cache directory and the cache path
	x.loc = filepath.Join(cacheDir, cachePath)
	return nil
}

// IsUpdated checks if the threat datasets are up-to-date.
// It returns a boolean value indicating whether the datasets are updated or not,
// and an error if there was an issue when checking the datasets' last modified date.
func (x *Maxm) IsUpdated() (bool, error) {
	// Get the location of the threat datasets
	if err := x.location(); err != nil {
		// If there was an error getting the location, return out and the error
		return false, err
	}

	req, res := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(res)
	req.Header.SetMethod(fasthttp.MethodHead)
	req.Header.SetUserAgent(user_agent)
	req.SetRequestURI(ASNURL)

	if err := fasthttp.Do(req, res); err != nil {
		return false, err
	}
	last_modified := unsafeConvert.StringSlice(res.Header.Peek("Last-Modified"))
	if last_modified == "" {
		return false, ErrNoModified
	}

	r, err := fsutil.OpenRead(filepath.Join(x.loc, "/modified"))
	if err != nil {
		return false, err
	}
	version := unsafeConvert.StringSlice(r)

	// Check if the last modified date is equal to the current date

	// Return the result and a nil error
	return version == last_modified, nil
}

func (x *Maxm) get(url, key string, update bool) error {
	req, res := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.SetUserAgent(user_agent)
	req.SetRequestURI(url)
	if err := fasthttp.Do(req, res); err != nil {
		return err
	}
	fasthttp.ReleaseRequest(req)
	if update {
		last_modified := unsafeConvert.StringSlice(res.Header.Peek("Last-Modified"))
		fsutil.TruncWrite(filepath.Join(x.loc, "/modified"), last_modified)
	}
	b := &bytes.Buffer{}
	b.Write(res.Body())
	defer b.Reset()
	fasthttp.ReleaseResponse(res)
	g_r, err := gzip.NewReader(b)
	if err != nil {
		return err
	}
	defer g_r.Close()
	if err := x.t_reader(tar.NewReader(g_r), key, filepath.Join(x.loc, "/"+key)); err != nil {
		return err
	}
	return nil
}

func (x *Maxm) t_reader(t *tar.Reader, key string, in string) error {
	for {
		// Read the next header from the tar archive
		header, err := t.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Skip non-regular files
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if header.Name != key {
			continue
		}

		// Read the contents of the file
		of, err := fsutil.OpenFile(in, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
		if err != nil {
			return err
		}
		_, err = io.Copy(of, t)
		if err != nil {
			return err
		}
		break
	}
	return nil
}
