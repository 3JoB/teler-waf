package maxm

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"

	"github.com/3JoB/ulib/fsutil"
	"github.com/3JoB/ulib/keyword/bms"
	"github.com/3JoB/unsafeConvert"
	"github.com/valyala/fasthttp"
)

type Maxm struct {
	loc string
}

// Get retrieves all the teler threat datasets.
//
// It returns an error if there was an issue when retrieving the datasets.
func (x *Maxm) Get() error {
	if fsutil.IsExist(x.loc) {
		// Delete existing threat datasets
		if err := os.RemoveAll(x.loc); err != nil {
			// If there was an error deleting the datasets, return the error
			return err
		}
	}

	// Create the destination directory if it doesn't exist
	if err := os.MkdirAll(x.loc, 0755); err != nil {
		// If there was an error creating the directory, return the error
		return err
	}

	if err := x.get(ASNURL, asn_key, asn_gz, true); err != nil {
		return err
	}
	if err := x.get(CityURL, city_key, city_gz, false); err != nil {
		return err
	}
	// Return a nil error
	return nil
}

// Return ASN, City
func (x *Maxm) GetName() (string, string) {
	return filepath.Join(x.loc, "/"+asn_key), filepath.Join(x.loc, "/"+city_key)
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
	var err error
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

	if !fsutil.IsExist(x.loc) {
		fsutil.Mkdir(x.loc)
	}

	mod_path := filepath.Join(x.loc, "/.modified")
	f, err := fsutil.OpenFile(mod_path, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return false, err
	}
	defer f.Close()
	r, err := fsutil.ReadAll(f)
	if err != nil {
		return false, err
	}
	version := unsafeConvert.StringSlice(r)

	// Check if the last modified date is equal to the current date

	// Return the result and a nil error
	return version != last_modified, nil
}

func (x *Maxm) get(url, key, zk string, update bool) error {
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
		fsutil.TruncWrite(filepath.Join(x.loc, "/.modified"), last_modified)
	}
	fs, err := fsutil.OpenFile(filepath.Join(x.loc, "/"+zk), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	fs.Write(res.Body())
	fs.Close()
	fs, err = fsutil.OpenFile(filepath.Join(x.loc, "/"+zk), os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	fasthttp.ReleaseResponse(res)
	if err := x.t_reader(fs, key, filepath.Join(x.loc, "/"+key)); err != nil {
		return err
	}
	return nil
}

func (x *Maxm) t_reader(r io.ReadCloser, key string, in string) error {
	g_r, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer g_r.Close()
	defer r.Close()
	t := tar.NewReader(g_r)
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

		if !bms.Find(header.Name, key) {
			continue
		}

		// Read the contents of the file
		of, err := fsutil.OpenFile(in, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			return err
		}
		d, err := fsutil.ReadAll(t)
		if err != nil {
			return err
		}
		of.Write(d)
		of.Close()
		break
	}

	return nil
}
