package maxm

import (
	"errors"

	"github.com/3JoB/ulib/litefmt"
)

var (
	ASNURL        string
	CityURL       string
	ErrNoModified = errors.New("last-modified is empty")
)

func Init(token string) {
	ASNURL = litefmt.Sprint(baseURL, asn_id, "&license_key=", token, "&suffix=tar.gz")
	CityURL = litefmt.Sprint(baseURL, city_id, "&license_key=", token, "&suffix=tar.gz")
}
