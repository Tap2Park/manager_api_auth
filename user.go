package auth

import (
	"database/sql"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"time"
)

var ErrUserInActive = errors.New("user account is inactive")
var ErrInvalidUserToken = errors.New("invalid User Token")

type Permissions struct {
	ManageTariff          bool `json:"manage_tariff"`
	ManagePermits         bool `json:"manage_permits"`
	ViewReports           bool `json:"view_reports"`
	ManageLocations       bool `json:"manage_locations"`
	ManageUsers           bool `json:"manage_users"`
	ManageContacts        bool `json:"manage_contacts"`
	ManageCustomerSupport bool `json:"manage_customer_support"`
	ViewAPI               bool `json:"view_api"`
	ManageAPI             bool `json:"manage_api"`
	BannedVehicles        bool `json:"banned_vehicles"`
	Marketing             bool `json:"marketing"`
	ExportData            bool `json:"export_data"`
}

// User represents a user in the system. It contains information such as ID, name, email, activity status, last login, entered date, entered by, token, password expiry date, permissions
type User struct {
	ID                 int            `json:"id"`
	Name               string         `json:"name"`
	Email              string         `json:"email"`
	Active             bool           `json:"active"`
	LastLogin          time.Time      `json:"last_login"`
	Entered            time.Time      `json:"entered"`
	EnteredBy          int            `json:"entered_by"`
	Tkn                string         `json:"tkn"`
	PasswordExpiryDate time.Time      `json:"password_expiry_date"`
	Permissions        Permissions    `json:"permissions"`
	ClientId           int            `json:"clientid"`
	Locations          map[int]string `json:"locations"`
	UserType           string         `json:"user_type"`
}

// Get retrieves user information from the database based on the provided user token.
//
// The user token is used to query the "bo_user" table and retrieve the user's details such as ID, name, email,
// active status, last login, entered date, entered by, token, password expiry date, and client ID.
//
// If the user token is not found in the database, the function returns ErrInvalidUserToken.
//
// If there is any unexpected error reading from the database, the function returns an error message with the
// details of the error.
//
// If the user is inactive, the function returns ErrUserInActive.
//
// The function also retrieves the user's permissions from the "bo_user_security" table, such as permissions to
// manage tariff, manage permits, view reports, manage locations, manage users, manage contacts, manage customer
// support, view API, manage API, banned vehicles, and marketing permissions.
//
// Additionally, the function retrieves the user's locations from the "bo_user_locations" table and stores them in
// the "Locations" field of the User struct.
//
// Finally, the function updates the "last_login" field of the "bo_user" table with the current timestamp.
//
// Usage:
//
//	usr := User{}
//	err := usr.Get(userTkn, db)
//	if err != nil {
//	    // handle error
//	}
//	// use usr for further processing
func (m *User) Get(userTkn string, db *sql.DB) error {

	sqlS := "SELECT id, name, email, active, last_login, entered, entered_by, tkn,password_expiry,clientid,user_type FROM bo_user WHERE tkn=?"
	var lastLogin sql.NullTime
	var passwordExpiry sql.NullTime

	err := db.QueryRow(sqlS, userTkn).Scan(&m.ID, &m.Name, &m.Email, &m.Active, &lastLogin, &m.Entered, &m.EnteredBy, &m.Tkn, &passwordExpiry, &m.ClientId, &m.UserType)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidUserToken
		} else {
			return fmt.Errorf("there was an unexpected error reading from the database: %v", err)
		}
	}

	if !m.Active {
		return ErrUserInActive
	}

	if lastLogin.Valid {
		m.LastLogin = lastLogin.Time
	}

	if passwordExpiry.Valid {
		m.PasswordExpiryDate = passwordExpiry.Time
	}

	// ------------------------------------------------------------------------
	// User Permissions
	// ------------------------------------------------------------------------

	sqlS = "SELECT manage_tariff, manage_permits, view_reports, manage_locations, manage_users, manage_contacts, manage_customer_support, view_api, manage_api,banned_vehicles,marketing FROM bo_user_security WHERE usrid=?"
	err = db.QueryRow(sqlS, m.ID).Scan(&m.Permissions.ManageTariff, &m.Permissions.ManagePermits, &m.Permissions.ViewReports, &m.Permissions.ManageLocations, &m.Permissions.ManageUsers, &m.Permissions.ManageContacts, &m.Permissions.ManageCustomerSupport, &m.Permissions.ViewAPI, &m.Permissions.ManageAPI, &m.Permissions.BannedVehicles, &m.Permissions.Marketing)
	if err != nil {
		log.Warnln(err)
	}

	// ------------------------------------------------------------------------
	// User Locations
	// ------------------------------------------------------------------------
	m.Locations = make(map[int]string, 0)

	sqlS = "SELECT locationid,coalesce((SELECT sitename FROM locations WHERE code=locationid),'') sitename FROM bo_user_locations WHERE locationid>0 and userid=?"
	rows, err := db.Query(sqlS, m.ID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Errorln(err)
		}
	} else {
		for rows.Next() {
			var lid int
			var sn string
			err = rows.Scan(&lid, &sn)
			if err != nil {
				log.Warnln(err)
			} else {
				m.Locations[lid] = sn
			}
		}
		_ = rows.Close()
	}
	// ------------------------------------------------------------------------

	_, err = db.Exec("UPDATE bo_user SET last_login=NOW() WHERE id=?", m.ID)
	if err != nil {
		log.Warnln(err)
	}

	return nil
}

// ------------------------------------------------------------------------------------------
func GetUser(userTkn string, db *sql.DB) (User, error) {

	usr := User{}
	err := usr.Get(userTkn, db)

	return usr, err
}

// ------------------------------------------------------------------------------------------
