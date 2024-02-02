using System;
using RestSharp;
using RestSharp.Authenticators;

namespace SharpBucket.Authentication
{
    /// <summary>
    /// This class helps you authenticate with the Bitbucket REST API via a bearer token.
    /// </summary>
    public sealed class BearerTokenAuthentication : Authenticate
    {
        private const string TokenType = "Bearer";
        private const int RefreshMargin = 5;

        private string BaseUrl { get; }
        private string AccessToken { get; set; }

        public BearerTokenAuthentication(string accessToken, string baseUrl)
        {
            AccessToken = accessToken;
            BaseUrl = baseUrl;
            Client = CreateClient();
        }

        private IRestClient CreateClient()
        {
            return new RestClient(BaseUrl)
            {
                Authenticator = new OAuth2AuthorizationRequestHeaderAuthenticator(AccessToken, TokenType)
            };
        }
    }
}
