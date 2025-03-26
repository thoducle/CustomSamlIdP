using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Text;
using System.Net;

public class SamlController : Controller
{
    private readonly IConfiguration _configuration;

    public SamlController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public IActionResult InitiateLogin()
    {
        var entityId = _configuration["Saml:EntityId"];
        var destinationUrl = _configuration["Saml:DestinationUrl"];

        // Generate a Dummy SAML Authentication Request (to satisfy Entra ID)
        string samlRequest = SamlRequestGenerator.GenerateSamlRequest(destinationUrl, entityId);

        // Redirect to Entra ID with the SAMLRequest
        string redirectUrl = $"{destinationUrl}?SAMLRequest={WebUtility.UrlEncode(samlRequest)}";

        return Redirect(redirectUrl);
    }


    public IActionResult Login()
    {
        var entityId = _configuration["Saml:EntityId"];
        var destinationUrl = _configuration["Saml:DestinationUrl"];
        var certPath = Path.Combine(Directory.GetCurrentDirectory(), _configuration["Saml:CertificatePath"]);
        var certPassword = _configuration["Saml:CertificatePassword"];

        // Simulated User Info
        string userEmail = "user@example.com";
        string accountNumber = "1234567890"; // Example extra claim

        // Generate a properly formatted and signed SAML response
        string samlResponseXml = SamlAssertionGenerator.GenerateSamlResponse(
            userEmail, entityId, destinationUrl, certPath, certPassword, accountNumber
        );

        // Ensure the SAML response is Base64-encoded
        string encodedSamlResponse = Convert.ToBase64String(Encoding.UTF8.GetBytes(samlResponseXml));

        // Entra ID may require a RelayState parameter (optional)
        string relayState = "https://myapps.microsoft.com/";

        // Create an HTML form to POST the SAML response to Entra ID
        var samlForm = $@"
    <html>
    <body onload='document.forms[0].submit();'>
        <form method='POST' action='{destinationUrl}'>
            <input type='hidden' name='SAMLResponse' value='{HtmlEncode(encodedSamlResponse)}'/>
            <input type='hidden' name='RelayState' value='{HtmlEncode(relayState)}'/>
            <input type='submit' value='Continue' />
        </form>
    </body>
    </html>";

        return Content(samlForm, "text/html");
    }


    private string HtmlEncode(string value)
    {
        return WebUtility.HtmlEncode(value);
    }

}
