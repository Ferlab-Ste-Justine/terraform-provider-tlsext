package provider

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func init() {
	schema.DescriptionKind = schema.StringMarkdown
}

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{},
		ResourcesMap: map[string]*schema.Resource{
			"tlsext_pgp_private_key": resourcePgpPrivateKey(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"tlsext_pem_chain": dataPemChain(),
		},
	}
}