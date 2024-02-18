using IdentityManagerApp.Data;
using IdentityManagerApp.Models;
using IdentityManagerApp.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace IdentityManagerApp.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(ApplicationDbContext context, UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var users = await _context.AppUsers.ToListAsync();

            foreach (var user in users)
            {
                var user_role = await _userManager.GetRolesAsync(user) as List<string>;
                user.Role = String.Join(",", user_role);

                var user_claim = (await _userManager.GetClaimsAsync(user)).Select(x=>x.Type);
                user.Claim = String.Join(",", user_claim);
            }

            return View(users);
        }

        [HttpGet]
        public async Task<IActionResult> ManageRole(string userId)
        {
            AppUser user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound();

            List<string> exsistingUserRoles = await _userManager.GetRolesAsync(user) as List<string>;
            RolesViewModel model = new()
            {
                User = user
            };

            foreach (var role in _roleManager.Roles)
            {
                RoleSelection roleSelection = new()
                {
                    RoleName = role.Name
                };

                if (exsistingUserRoles.Any(x => x == role.Name))
                {
                    roleSelection.IsSelected = true;
                }
                model.RolesList.Add(roleSelection);
            }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRole(RolesViewModel model)
        {
            AppUser user = await _userManager.FindByIdAsync(model.User.Id);
            if (user == null)
                return NotFound();

            var userOldRoles = await _userManager.GetRolesAsync(user);
            var result = await _userManager.RemoveFromRolesAsync(user, userOldRoles);
            if (!result.Succeeded)
                return View(model);

            result = await _userManager.AddToRolesAsync(user,
                model.RolesList.Where(x => x.IsSelected).Select(c => c.RoleName));
            if (!result.Succeeded)
                return View(model);

            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> ManageClaim(string userId)
        {
            AppUser user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound();

            var exsistingUserClaims = await _userManager.GetClaimsAsync(user);
            ClaimsViewModel model = new()
            {
                User = user
            };

            foreach (Claim claim in ClaimStore.claimsList)
            {
                ClaimSelection claimSelection = new()
                {
                    ClaimType = claim.Type
                };

                if (exsistingUserClaims.Any(x => x.Type == claim.Type))
                {
                    claimSelection.IsSelected = true;
                }
                model.ClaimsList.Add(claimSelection);
            }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageClaim(ClaimsViewModel model)
        {
            AppUser user = await _userManager.FindByIdAsync(model.User.Id);
            if (user == null) return NotFound();

            var oldClaims = await _userManager.GetClaimsAsync(user);
            var result = await _userManager.RemoveClaimsAsync(user, oldClaims);

            if (!result.Succeeded)
                return View(model);

            result = await _userManager.AddClaimsAsync(user,
                model.ClaimsList.Where(x => x.IsSelected).Select(c => new Claim(c.ClaimType, c.IsSelected.ToString())));

            if (!result.Succeeded)
                return View(model);

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LockUnlock(string userId)
        {
            AppUser user = await _context.AppUsers.FirstOrDefaultAsync(x => x.Id == userId);
            if (user == null)
                return NotFound();

            if (user.LockoutEnd != null && user.LockoutEnd > DateTime.Now)
            {
                user.LockoutEnd = DateTime.Now;
            }
            else
            {
                user.LockoutEnd = DateTime.Now.AddMonths(3);
            }
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteUser(string userId)
        {
            AppUser user = await _context.AppUsers.FirstOrDefaultAsync(x => x.Id == userId);
            if (user == null) return NotFound();

            _context.AppUsers.Remove(user);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
    }
}
