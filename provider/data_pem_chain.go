package provider

import (
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func dataPemChain() *schema.Resource {
	return &schema.Resource{
		Description: "Convenience to retrieve a list of elements from an input pem chain concaneted as a string. Aims to be more flexible and robust than using a regex.",
		Read:   dataPemChainRead,
		Schema: map[string]*schema.Schema{
			"pem_chain": {
				Description: "Concatenated pem chain to parse.",
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},
			"first_pem": {
				Description: "First pem element that was encountered in the chain.",
				Type:     schema.TypeString,
				Computed: true,
			},
			"last_pem": {
				Description: "Last pem element that was encountered in the chain.",
				Type:     schema.TypeString,
				Computed: true,
			},
			"pem_list": {
				Description: "Ordered list of pem elements in the same order they were encountered in the chain.",
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func dataPemChainRead(d *schema.ResourceData, meta interface{}) error {
	pemChain := []byte(d.Get("pem_chain").(string))

	hash := sha256.New()
	_, hashWriteErr := hash.Write(pemChain)
	if hashWriteErr != nil {
		return errors.New(fmt.Sprintf("Failed to hash pem chain to get id: %s.", hashWriteErr.Error()))
	}
	
	d.SetId(fmt.Sprintf("%x", hash.Sum(nil)))

	pemList := []string{}

	var certBlock *pem.Block
	certBlock, pemChain = pem.Decode(pemChain)
	if certBlock == nil {
		return errors.New(fmt.Sprintf("Failed to read anything in the pem chain"))
	}

	d.Set("first_pem", string(pem.EncodeToMemory(certBlock)))

	for certBlock != nil {
		currentPem := string(pem.EncodeToMemory(certBlock))

		pemList = append(pemList, currentPem)

		certBlock, pemChain = pem.Decode(pemChain)
		if certBlock == nil {
			d.Set("last_pem", currentPem)
		}
	}

	d.Set("pem_list", pemList)

	return nil
}