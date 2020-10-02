﻿using System;
using RestSharp;
using RestSharp.Authenticators;

namespace SharpBucket.Authentication
{
    /// <summary>
    /// This class helps you authenticate with the Bitbucket REST API via the 2 legged OAuth authentication.
    /// </summary>
    [Obsolete("Use OAuth1TwoLeggedAuthentication instead")]
    public sealed class OAuthentication2Legged : OauthAuthentication
    {
        public OAuthentication2Legged(string consumerKey, string consumerSecret, string baseUrl)
            : base(consumerKey, consumerSecret, baseUrl)
        {
            Client = new RestClient(baseUrl)
            {
                Authenticator = OAuth1Authenticator.ForProtectedResource(ConsumerKey, ConsumerSecret, null, null)
            };
        }
    }
}