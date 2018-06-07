using EVEStandard.ASPNETCoreSample.Models;
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

            var model = new SecurePageViewModel
            {
                CharacterName = characterInfo.Model.Name,
                CorporationName = corporationInfo.Model.Name
            };

            return View(model);
        }
    }
}