using HelperSharp;
using Microsoft.IdentityModel.Tokens;
using RestSharp;
using SalesforceSharp.Serialization;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;


namespace SalesforceSharp.Security
{
    /// <summary>
    /// With the OAuth 2.0 JWT bearer token flow, the client posts a JWT to the Salesforce OAuth token endpoint. 
    /// Salesforce processes the JWT, which includes a digital signature, and issues an access token based on prior approval of the app.
    /// 
    /// <remarks>
    /// More info at:
    /// https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm&amp;type=5
    /// </remarks>
    /// </summary>
    public class JwtBearerAuthenticationFlow : IAuthenticationFlow
    {
        #region Fields
        private IRestClient m_restClient;
        private string m_clientId;
        private string m_username;
        private string m_pfxFilePassword;
        private string m_pfxFilePath;
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes a new instance of the <see cref="JwtBearerAuthenticationFlow"/> class.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="username">The salesforce username.</param>
        /// <param name="pfxFilePassword">Password for the pfx key file.</param>
        public JwtBearerAuthenticationFlow(string clientId, string username, string pfxFilePassword) :
            this(new RestClient(), clientId, username, pfxFilePassword)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtBearerAuthenticationFlow"/> class.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="username">The salesforce username.</param>
        /// <param name="pfxFilePassword">Password for the pfx key file.</param>
        /// <param name="pfxFilePath">Path to the local pfx key file.</param>
        public JwtBearerAuthenticationFlow(string clientId, string username, string pfxFilePassword, string pfxFilePath) :
            this(new RestClient(), clientId, username, pfxFilePassword, pfxFilePath)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtBearerAuthenticationFlow"/> class.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="username">The salesforce username.</param>
        /// <param name="pfxFilePassword">Password for the pfx key file.</param>
        /// <param name="pfxFilePath">Path to the local pfx key file.</param>
        /// <param name="tokenRequestEndpointUrl">The token request endpoint url.</param>
        public JwtBearerAuthenticationFlow(string clientId, string username, string pfxFilePassword, string pfxFilePath, string tokenRequestEndpointUrl) :
            this(new RestClient(), clientId, username, pfxFilePassword, pfxFilePath, tokenRequestEndpointUrl)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtBearerAuthenticationFlow"/> class.
        /// </summary>
        /// <param name="restClient">The REST client which will be used.</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="pfxFilePassword">Password for the pfx key file.</param>
        /// <param name="username">The salesforce username.</param>
        /// <param name="pfxFilePath">Path to the local pfx key file.</param>
        /// <param name="tokenRequestEndpointUrl">The token request endpoint url.</param>
        internal JwtBearerAuthenticationFlow(IRestClient restClient, string clientId, string username, string pfxFilePassword, string pfxFilePath = "./server.pfx", string tokenRequestEndpointUrl = "https://login.salesforce.com/services/oauth2/token")
        {
            ExceptionHelper.ThrowIfNull("restClient", restClient);
            ExceptionHelper.ThrowIfNull("clientId", clientId);
            ExceptionHelper.ThrowIfNull("username", username);
            ExceptionHelper.ThrowIfNull("pfxFilePassword", pfxFilePassword);

            m_restClient = restClient;
            m_clientId = clientId;
            m_username = username;
            m_pfxFilePassword = pfxFilePassword;
            m_pfxFilePath = pfxFilePath;
            TokenRequestEndpointUrl = tokenRequestEndpointUrl;
        }
        #endregion

        #region Properties
        /// <summary>
        /// Gets or sets the token request endpoint url.
        /// </summary>
        /// <remarks>
        /// The default value is https://login.salesforce.com/services/oauth2/token.
        /// For sandbox use "https://test.salesforce.com/services/oauth2/token.
        /// </remarks>
        public string TokenRequestEndpointUrl { get; set; }
        #endregion

        #region Methods
        /// <summary>
        /// Authenticate in the Salesforce REST's API.
        /// </summary>
        /// <returns>
        /// The authentication info with access token and instance url for futher API calls.
        /// </returns>
        /// <remarks>
        /// If authentiaction fails an SalesforceException will be throw.
        /// </remarks>
        public AuthenticationInfo Authenticate()
        {
            if (ServicePointManager.SecurityProtocol != 0)
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            }
            Uri uri = new Uri(TokenRequestEndpointUrl);
            m_restClient.BaseUrl = uri;

            var request = new RestRequest(Method.POST)
            {
                RequestFormat = DataFormat.Json
            };

            var jwtToken = CreateClientAuthJwt();

            request.AddParameter("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
            request.AddParameter("assertion", jwtToken);

            var response = m_restClient.Post(request);
            var isAuthenticated = response.StatusCode == HttpStatusCode.OK;

            var deserializer = new GenericJsonDeserializer(new SalesforceContractResolver(false));
            var responseData = deserializer.Deserialize<dynamic>(response);

            if (responseData == null)
                throw new SalesforceException(response.ErrorException.Message, response.ErrorMessage);

            if (isAuthenticated)
            {
                return new AuthenticationInfo(responseData.access_token.Value, responseData.instance_url.Value);
            }
            else
            {
                throw new SalesforceException(responseData.error.Value, responseData.error_description.Value);
            }
        }

        /// <summary>
        /// Create JWT token
        /// </summary>
        /// <returns>
        /// The JWT token to be passed to auth server
        /// </returns>
        private string CreateClientAuthJwt()
        {
            var tokenHandler = new JwtSecurityTokenHandler { TokenLifetimeInMinutes = 25 };
            var securityToken = tokenHandler.CreateJwtSecurityToken(
                issuer: m_clientId, // issuer must be the client ID you were provided
                audience: TokenRequestEndpointUrl, // audience must be the identity provider
                subject: new ClaimsIdentity(new List<Claim> { new Claim(JwtRegisteredClaimNames.Sub, m_username), new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) }),
                signingCredentials: new SigningCredentials(new X509SecurityKey(new X509Certificate2(m_pfxFilePath, m_pfxFilePassword)), "RS256"));
            return tokenHandler.WriteToken(securityToken);
        }
        #endregion
    }
}