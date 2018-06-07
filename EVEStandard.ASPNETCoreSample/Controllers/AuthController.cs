using EVEStandard.Models.SSO;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace EVEStandard.ASPNETCoreSample.Controllers
{
    public class AuthController : Controller
    {
        private readonly EVEStandardAPI esiClient;

        private static string SSOStateKey = "SSOState";

        public AuthController(EVEStandardAPI esiClient)
        {
            this.esiClient = esiClient;
        }

        public IActionResult Login(string returnUrl = null)
        {
            // Scopes are required for API calls but not for authentication, dummy scope is inserted to workaround an issue in the library
            var scopes = new List<string>()
            {
                String.Empty
            };

            string state;

            if (!String.IsNullOrEmpty(returnUrl))
            {
                state = Base64UrlTextEncoder.Encode(Encoding.ASCII.GetBytes(returnUrl));
            }
            else
            {
                state = Guid.NewGuid().ToString();
            }

            HttpContext.Session.SetString(SSOStateKey, state);

            var authorization = esiClient.SSO.AuthorizeToEVEUri(scopes, state);
            return Redirect(authorization.SignInURI);
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> Callback(string code, string state)
        {
            var authorization = new Authorization
            {
                AuthorizationCode = code,
                ExpectedState = HttpContext.Session.GetString(SSOStateKey),
                ReturnedState = state
            };

            var accessToken = await esiClient.SSO.VerifyAuthorizationAsync(authorization);
            var character = await esiClient.SSO.GetCharacterDetailsAsync(accessToken.AccessToken);

            await SignInAsync(character.CharacterID, character.CharacterName);
                       
            if (Guid.TryParse(state, out Guid stateGuid))
            {
                return RedirectToAction("Index", "Home");
            }
            else
            {
                var returnUrl = Encoding.ASCII.GetString(Base64UrlTextEncoder.Decode(state));
                return Redirect(returnUrl);
            }            
        }

        private async Task SignInAsync(int characterId, string characterName)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, characterId.ToString()),
                new Claim(ClaimTypes.Name, characterName)
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                new AuthenticationProperties { IsPersistent = true, ExpiresUtc = DateTime.UtcNow.AddHours(24) });
        }
    }
}