﻿using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using RestSharp;
using SharpBucket.Authentication;
using SharpBucket.Utility;

namespace SharpBucket
{
    /// <summary>
    /// A client for the Bitbucket API. It supports V1 and V2 of the API.
    /// More info:
    /// https://confluence.atlassian.com/display/BITBUCKET/Use+the+Bitbucket+REST+APIs
    /// </summary>
    public abstract class SharpBucket : ISharpBucket
    {
        private Authenticate authenticator;

        /// <summary>
        /// The base URL exposing the Bitbucket API.
        /// </summary>
        protected string BaseUrl { get; }

        private RequestExecutor RequestExecutor { get; }

        internal SharpBucket(string baseUrl, RequestExecutor requestExecutor)
        {
            this.BaseUrl = baseUrl;
            this.RequestExecutor = requestExecutor;
            NoAuthentication();
        }

        /// <summary>
        /// Do not use authentication with the Bitbucket API. Only public data can be retrieved.
        /// </summary>
        public void NoAuthentication()
        {
            authenticator = new NoAuthentication(BaseUrl) { RequestExecutor = this.RequestExecutor };
        }

        /// <summary>   
        /// Use basic authentication with the Bitbucket API. OAuth authentication is preferred over
        /// basic authentication, due to security reasons.
        /// </summary>
        /// <param name="username">Your Bitbucket user name.</param>
        /// <param name="password">Your Bitbucket password.</param>
        public void BasicAuthentication(string username, string password)
        {
            authenticator = new BasicAuthentication(username, password, BaseUrl) { RequestExecutor = this.RequestExecutor };
        }

        /// <summary>   
        /// Use bearer token authentication with the Bitbucket API.
        /// </summary>
        /// <param name="token">The bearer token.</param>
        public void BearerTokenAuthentication(string token)
        {
            authenticator = new BearerTokenAuthentication(token, BaseUrl) { RequestExecutor = this.RequestExecutor };
        }

        /// <summary>
        /// Use 2 legged OAuth 1.0a authentication. This is similar to basic authentication, since
        /// it requires the same number of steps. It is still safer to use than basic authentication, 
        /// since you can revoke the API keys.
        /// More info:
        /// https://confluence.atlassian.com/display/BITBUCKET/OAuth+on+Bitbucket
        /// </summary>
        /// <param name="consumerKey">Your consumer API key obtained from the Bitbucket web page.</param>
        /// <param name="consumerSecretKey">Your consumer secret API key also obtained from the Bitbucket web page.</param>
        public void OAuth1TwoLeggedAuthentication(string consumerKey, string consumerSecretKey)
        {
            authenticator = new OAuth1TwoLeggedAuthentication(consumerKey, consumerSecretKey, BaseUrl) { RequestExecutor = this.RequestExecutor };
        }

        /// <summary>
        /// Use 3 legged OAuth 1.0a authentication. This is the most secure one, but for simple uses it might
        /// be a bit too complex.
        /// More info:
        /// https://confluence.atlassian.com/display/BITBUCKET/OAuth+on+Bitbucket
        /// </summary>
        /// <param name="consumerKey">Your consumer API key obtained from the Bitbucket web page.</param>
        /// <param name="consumerSecretKey">Your consumer secret API key also obtained from the Bitbucket web page.</param>
        /// <param name="callback">Callback URL to which Bitbucket will send the pin.</param>
        /// <returns></returns>
        public OAuth1ThreeLeggedAuthentication OAuth1ThreeLeggedAuthentication(
            string consumerKey,
            string consumerSecretKey,
            string callback = "oob")
        {
            var oauth1ThreeLeggedAuthentication = new OAuth1ThreeLeggedAuthentication(consumerKey, consumerSecretKey, callback, BaseUrl) { RequestExecutor = this.RequestExecutor };
            authenticator = oauth1ThreeLeggedAuthentication;
            return oauth1ThreeLeggedAuthentication;
        }

        /// <summary>
        /// Use 3 legged OAuth 1.0a authentication. Use this method if you have already obtained the OAuthToken
        /// and OAuthSecretToken. This method can be used so you do not have to go through the whole 3 legged
        /// process every time. You can save the tokens you receive the first time and reuse them in another session.
        /// </summary>
        /// <param name="consumerKey">Your consumer API key obtained from the Bitbucket web page.</param>
        /// <param name="consumerSecretKey">Your consumer secret API key also obtained from the Bitbucket web page.</param>
        /// <param name="oauthToken">Your OAuth token that was obtained on a previous session.</param>
        /// <param name="oauthTokenSecret">Your OAuth secret token that was obtained on a previous session.</param>
        /// <returns></returns>
        public void OAuth1ThreeLeggedAuthentication(
            string consumerKey,
            string consumerSecretKey,
            string oauthToken,
            string oauthTokenSecret)
        {
            authenticator = new OAuth1ThreeLeggedAuthentication(
                consumerKey,
                consumerSecretKey,
                oauthToken,
                oauthTokenSecret,
                BaseUrl)
            {
                RequestExecutor = this.RequestExecutor
            };
        }

        /// <summary>
        /// Use Oauth2 authentication. This is the newest version and is preferred.
        /// </summary>
        /// <param name="consumerKey"></param>
        /// <param name="consumerSecretKey"></param>
        /// <returns></returns>
        public void OAuth2ClientCredentials(string consumerKey, string consumerSecretKey)
        {
            authenticator = new OAuth2ClientCredentials(consumerKey, consumerSecretKey, BaseUrl) { RequestExecutor = this.RequestExecutor };
        }

        /// <summary>
        /// Allows the use of a mock IRestClient, for testing.
        /// </summary>
        /// <param name="client"></param>
        internal void MockAuthentication(IRestClient client)
        {
            authenticator = new MockAuthentication(client, BaseUrl) { RequestExecutor = this.RequestExecutor };
        }

        private Method ToRestSharpEnum(HttpMethod method)
        {
            return (Method)Enum.Parse(typeof(Method), method.Method, true);
        }

        string ISharpBucketRequester.Send(HttpMethod method, object body, string relativeUrl, object requestParameters)
        {
            var restSharpMethod = ToRestSharpEnum(method);
            var parameterDictionary = requestParameters.ToDictionary();
            return authenticator.GetResponse(relativeUrl, restSharpMethod, body, parameterDictionary);
        }

        async Task<string> ISharpBucketRequester.SendAsync(HttpMethod method, object body, string relativeUrl, object requestParameters, CancellationToken token)
        {
            var restSharpMethod = ToRestSharpEnum(method);
            var parameterDictionary = requestParameters.ToDictionary();
            return await authenticator.GetResponseAsync(relativeUrl, restSharpMethod, body, parameterDictionary, token);
        }

        T ISharpBucketRequester.Send<T>(HttpMethod method, object body, string relativeUrl, object requestParameters)
        {
            var restSharpMethod = ToRestSharpEnum(method);
            var parameterDictionary = requestParameters.ToDictionary();
            return authenticator.GetResponse<T>(relativeUrl, restSharpMethod, body, parameterDictionary);
        }

        async Task<T> ISharpBucketRequester.SendAsync<T>(HttpMethod method, object body, string relativeUrl, object requestParameters, CancellationToken token)
        {
            var restSharpMethod = ToRestSharpEnum(method);
            var parameterDictionary = requestParameters.ToDictionary();
            return await authenticator.GetResponseAsync<T>(relativeUrl, restSharpMethod, body, parameterDictionary, token);
        }

        Uri ISharpBucketRequester.GetRedirectLocation(string relativeUrl, object requestParameters)
        {
            var parameterDictionary = requestParameters.ToDictionary();
            return authenticator.GetRedirectLocation(relativeUrl, parameterDictionary);
        }

        async Task<Uri> ISharpBucketRequester.GetRedirectLocationAsync(string relativeUrl, object requestParameters, CancellationToken token)
        {
            var parameterDictionary = requestParameters.ToDictionary();
            return await authenticator.GetRedirectLocationAsync(relativeUrl, parameterDictionary, token);
        }
    }
}