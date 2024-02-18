using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManagerApp.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        // anyone can access this
        [AllowAnonymous]
        public IActionResult AllAccess()
        {
            return View();
        }

        //anyone that has logged in can access
        public IActionResult AuthorizedAccess()
        {
            return View();
        }

        //account with role of user or admin can access
        [Authorize(Roles = $"{SD.Admin},{SD.User}")]
        public IActionResult UserOrAdminRoleAccess()
        {
            return View();
        }

        //account with role of user and admin can access
        [Authorize(Roles = "AdminAndUser")]
        public IActionResult UserAndAdminRoleAccess()
        {
            return View();
        }

        //account with role of admin can access
        [Authorize(Policy = "Admin")]
        public IActionResult AdminRoleAccess()
        {
            return View();
        }

        //account with role and create Claim can access
        [Authorize(Policy = "AdminRole_CreateClaim")]
        public IActionResult Admin_Create_Access()
        {
            return View();
        }

        //account with role and create, edit, delete Claim can access
        [Authorize(Policy = "AdminRole_CreateEditDeleteClaim")]
        public IActionResult Admin_Create_Edit_Delete_Access()
        {
            return View();
        }
    }
}
