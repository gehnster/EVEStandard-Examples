using EVEStandard.ASPNETCoreSample.Models;
using EVEStandard.Models.API;
using EVEStandard.Models.SSO;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace EVEStandard.ASPNETCoreSample.Controllers
{
    [Authorize]
    public class SecureController : Controller
    {
        private readonly EVEStandardAPI esiClient;

        public SecureController(EVEStandardAPI esiClient)
        {
            this.esiClient = esiClient;
        }

        public async Task<IActionResult> Index()
        {
            var characterId = Int32.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value);
            var characterInfo = await esiClient.Character.GetCharacterPublicInfoV4Async(characterId);
            var corporationInfo = await esiClient.Corporation.GetCorporationInfoV4Async((int)characterInfo.Model.CorporationId);

            var auth = new AuthDTO
            {
                AccessToken = new AccessTokenDetails
                {
                    AccessToken = User.FindFirstValue("AccessToken"),
                    ExpiresUtc = DateTime.Parse(User.FindFirstValue("AccessTokenExpiry")),
                    RefreshToken = User.FindFirstValue("RefreshToken")                   
                },
                CharacterId = characterId,
                Scopes = User.FindFirstValue("Scopes")
            };

            var locationInfo = await esiClient.Location.GetCharacterLocationV1Async(auth);
            var location = await esiClient.Universe.GetSolarSystemInfoV3Async(locationInfo.Model.SolarSystemId);

            var model = new SecurePageViewModel
            {
                CharacterName = characterInfo.Model.Name,
                CorporationName = corporationInfo.Model.Name,
                CharacterLocation = location.Model.Name
            };

            return View(model);
        }
    }
}