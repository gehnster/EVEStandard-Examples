using EVEStandard.Models.SSO;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace EVEStandard.ASPNETCoreSample.Controllers
{
    public class AuthController : Controller
    {
        private readonly EVEStandardAPI _esiClient;
        private readonly SSOv2 _sso;

        private static string SSOStateKey = "SSOState";

        public AuthController(EVEStandardAPI esiClient, SSOv2 sso)
        {
            _esiClient = esiClient;
            _sso = sso;
        }

        public IActionResult Login(string returnUrl = null)
        {
            // Scopes are required for API calls but not for authentication, dummy scope is inserted to workaround an issue in the library
            var scopes = new List<string>()
            {
                "esi-location.read_location.v1"
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

            var authorization = _sso.AuthorizeToSSOBasicAuthUri(state, scopes);
            return Redirect(authorization);
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> Callback(string code, string state)
        {
            var expectedState = HttpContext.Session.GetString(SSOStateKey);
            if(expectedState != state)
            {
                var fakeLogging = "You probably have a security issue if these two items don't match!";
            }

            var accessToken = await _sso.VerifyAuthorizationForBasicAuthAsync(code);
            var character = await _sso.GetCharacterDetailsAsync(accessToken.AccessToken);

            await SignInAsync(accessToken, character);
                       
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

        private async Task SignInAsync(AccessTokenDetails accessToken, CharacterDetails character)
        {
            if (accessToken == null)
                throw new ArgumentNullException(nameof(accessToken));
            if (character == null)
                throw new ArgumentNullException(nameof(character));

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, character.CharacterId.ToString()),
                new Claim(ClaimTypes.Name, character.CharacterName),
                new Claim("AccessToken", accessToken.AccessToken),
                new Claim("RefreshToken", accessToken.RefreshToken ?? ""),
                new Claim("AccessTokenExpiry", accessToken.ExpiresUtc.ToString()),
                new Claim("Scopes", JsonSerializer.Serialize(character.Scopes))
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                new AuthenticationProperties { IsPersistent = true, ExpiresUtc = DateTime.UtcNow.AddHours(24) });
        }
    }
}