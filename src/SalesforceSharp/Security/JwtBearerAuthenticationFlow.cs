using System.Net;
using HelperSharp;
using RestSharp;
using SalesforceSharp.Serialization;
using System;


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
        private string m_jwtToken;
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes a new instance of the <see cref="JwtBearerAuthenticationFlow"/> class.
        /// </summary>
        /// <param name="jwtToken">The JWT Token</param>
        public JwtBearerAuthenticationFlow(string jwtToken) :
            this(new RestClient(), jwtToken)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtBearerAuthenticationFlow"/> class.
        /// </summary>
        /// <param name="jwtToken">The JWT Token</param>
        /// <param name="tokenRequestEndpointUrl">The token request endpoint url.</param>
        public JwtBearerAuthenticationFlow(string jwtToken, string tokenRequestEndpointUrl) :
            this(new RestClient(), jwtToken, tokenRequestEndpointUrl)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtBearerAuthenticationFlow"/> class.
        /// </summary>
        /// <param name="restClient">The REST client which will be used.</param>
        /// <param name="jwtToken">The JWT Token</param>
        /// <param name="tokenRequestEndpointUrl">The token request endpoint url.</param>
        internal JwtBearerAuthenticationFlow(IRestClient restClient, string jwtToken, string tokenRequestEndpointUrl = "https://login.salesforce.com/services/oauth2/token")
        {
            ExceptionHelper.ThrowIfNull("restClient", restClient);
            ExceptionHelper.ThrowIfNullOrEmpty("jwtToken", jwtToken);
            m_restClient = restClient;
            m_jwtToken = jwtToken;
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
            request.AddParameter("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
            request.AddParameter("assertion", m_jwtToken);

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
        #endregion
    }
}