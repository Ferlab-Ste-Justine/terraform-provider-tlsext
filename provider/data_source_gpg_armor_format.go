package provider

import (
	"crypto"
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/ProtonMail/go-crypto/openpgp"
	opengpgEcdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func dataSourceGpgArmorFormat() *schema.Resource {
	return &schema.Resource{
		Description: "Convert a public/private key pair into gpg format to sign commits.",
		Read: dataSourceGpgArmorFormatRead,
		Schema: map[string]*schema.Schema{
			"private_key": {
				Description: "Private part of the key, in pem format.",
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},
			"algorithm": {
				Description: "Algorithm of the encryption. The following values are supported: rsa, ecdsa.",
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					v := val.(string)
					if v != "rsa" && v != "ecdsa" {
						return []string{}, []error{errors.New("Permitted value for algorithm can only be one of the following: rsa, ecdsa.")}
					}

					return []string{}, []error{}
				},
			},
			"timestamp": {
				Description: "Timestamp needed by pgp.",
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.IsRFC3339Time,
			},
			"name": {
				Description: "Name to associate with the gpg key.",
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},
			"email": {
				Description: "Email to associate with the gpg key.",
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},
			"gpg_armor_public_key": &schema.Schema{
				Description: "Gpg armor format public key.",
				Type:     schema.TypeString,
				Computed: true,
			},
			"gpg_armor_private_key": &schema.Schema{
				Description: "Gpg armor format private key.",
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func GetParsedKeyFromPemFormat(privatePemKey string) (any, error) {
	priBlock, _ := pem.Decode([]byte(privatePemKey))
	if priBlock == nil || priBlock.Type != "PRIVATE KEY" {
		return nil, errors.New("Failed to decode pem encoded private_key.")
	}

	key, keyErr := x509.ParsePKCS8PrivateKey(priBlock.Bytes)
	if keyErr != nil {
		return nil, errors.New(fmt.Sprintf("Failed to parse private_key: %s.", keyErr.Error()))
	}

	return key, nil
}

func GetOpenPgpEntityFromParsedKey(key any, algorithm string, name string, email string, timestamp time.Time) (*openpgp.Entity, *packet.Config, error) {
	config := &packet.Config{DefaultHash: crypto.SHA256}
	entity, entityErr := openpgp.NewEntity(name, "", email, config)
	if entityErr != nil {
		return nil, nil, errors.New(fmt.Sprintf("Failed to build formated keys: %s.", entityErr.Error()))
	}

	if algorithm == "rsa" {
		rsaKey := key.(*rsa.PrivateKey)
		rsaPubKey := rsaKey.Public().(*rsa.PublicKey)
		entity.PrimaryKey = packet.NewRSAPublicKey(timestamp, rsaPubKey)
		entity.PrivateKey = packet.NewRSAPrivateKey(timestamp, rsaKey)
	} else {
		ecdsaKey := key.(*ecdsa.PrivateKey)
		ecdsaPubKey := ecdsaKey.Public().(*ecdsa.PublicKey)
		opengpgEcdsaKey := opengpgEcdsa.PrivateKey{PublicKey: opengpgEcdsa.PublicKey{X: (*ecdsaKey).PublicKey.X, Y: (*ecdsaKey).PublicKey.Y}, D: (*ecdsaKey).D}
		opengpgEcdsaPubKey := opengpgEcdsa.PublicKey{X: (*ecdsaPubKey).X, Y: (*ecdsaPubKey). Y}
		entity.PrimaryKey = packet.NewECDSAPublicKey(timestamp, &opengpgEcdsaPubKey)
		entity.PrivateKey = packet.NewECDSAPrivateKey(timestamp, &opengpgEcdsaKey)
	}

	for _, id := range entity.Identities {
		signatureErr := id.SelfSignature.SignUserId(id.UserId.Id, entity.PrimaryKey, entity.PrivateKey, config)
		if signatureErr != nil {
			return nil, nil, errors.New(fmt.Sprintf("Failed to self sign identity: %s.", signatureErr.Error()))
		}
	}

	return entity, config, nil
} 

type GpgEncoderWriter struct {
	EncodedValue string
}

func (writer *GpgEncoderWriter) Write(p []byte) (n int, err error) {
	writer.EncodedValue += string(p)
	return len(p), nil
}

func GetArmorEncodedKeyFromEntity(entity *openpgp.Entity, config *packet.Config, private bool) (string, error) {
	keyType := openpgp.PublicKeyType
	keyMsgString := "public"
	if private {
		keyType = openpgp.PrivateKeyType
		keyMsgString = "private"
	}

	encKey := GpgEncoderWriter{}
	keyWriter, encodeErr := armor.Encode(&encKey, keyType, nil)
	if encodeErr != nil {
		return "", errors.New(fmt.Sprintf("Failed to encode %s key in gpg armor format: %s.", keyMsgString, encodeErr.Error()))
	}

	var serErr error
	if !private {
		serErr = entity.Serialize(keyWriter)
	} else {
		serErr = entity.SerializePrivate(keyWriter, config)
	}

	if serErr != nil {
		return "", errors.New(fmt.Sprintf("Failed to encode %s key in gpg armor format: %s.", keyMsgString, serErr.Error()))
	}

	closeErr := keyWriter.Close()
	if closeErr != nil {
		return "", errors.New(fmt.Sprintf("Failed to encode %s key in gpg armor format: %s.", keyMsgString, closeErr.Error()))
	}

	return encKey.EncodedValue, nil
}

func dataSourceGpgArmorFormatRead(d *schema.ResourceData, meta interface{}) error {
	privateKeyPem := d.Get("private_key").(string)
	algorithm := d.Get("algorithm").(string)
	timestamp := d.Get("timestamp").(string)
	name := d.Get("name").(string)
	email := d.Get("email").(string)

	parsedTimestamp, timeerr := time.Parse(time.RFC3339, timestamp)
	if timeerr != nil {
		return errors.New(fmt.Sprintf("Failed to parse timestamp: %s.", timeerr.Error()))
	}

	key, keyErr := GetParsedKeyFromPemFormat(privateKeyPem)
	if keyErr != nil {
		return keyErr
	}

	entity, config, entityErr := GetOpenPgpEntityFromParsedKey(key, algorithm, name, email, parsedTimestamp)
	if entityErr != nil {
		return entityErr
	}

	priKey, priKeyErr := GetArmorEncodedKeyFromEntity(entity, config, true)
	if priKeyErr != nil {
		return priKeyErr
	}

	pubKey, pubKeyErr := GetArmorEncodedKeyFromEntity(entity, config, false)
	if pubKeyErr != nil {
		return pubKeyErr
	}

	d.Set("gpg_armor_private_key", priKey)
	d.Set("gpg_armor_public_key", pubKey)
	d.SetId(pubKey)

	return nil
}