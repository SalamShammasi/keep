
export interface ProviderAuthConfig {
  name: string;
  description: string;
  hint?: string;
  placeholder?: string;
  validation: string; // regex
  required?: boolean;
  value?: string;
  sensitive?: boolean;
}

export interface Provider {
  // key value pair of auth method name and auth method config
  config: {
    [configKey: string]: ProviderAuthConfig;
  };
  // whether the provider is installed or not
  installed: boolean;
  // if the provider is installed, this will be the auth details
  //  otherwise, this will be null
  details: {
    authentication: {
      [authKey: string]: string;
    };
  };
  // the name of the provider
  id: string;
  // the name of the provider
  comingSoon?: boolean;
}

export interface Providers {
  [providerName: string]: Provider;
}

export const defaultProvider: Provider = {
  config: {}, // Set default config as an empty object
  installed: false, // Set default installed value
  details: { authentication: {} }, // Set default authentication details as an empty object
  id: "", // Placeholder for the provider ID
};
