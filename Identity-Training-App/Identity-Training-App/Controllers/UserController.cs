using Identity_Training_App.Data;
using Identity_Training_App.Models;
using Identity_Training_App.Models.View_Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Identity_Training_App.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _usermanager;

        public UserController(ApplicationDbContext db,UserManager<IdentityUser> userManager)
        {
            _db = db;
            _usermanager = userManager;
        }
        public IActionResult Index()
        {
            var userlist = _db.ApplicationUser.ToList();
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            foreach(var user in userlist)
            {
                var role = userRole.FirstOrDefault(u=> u.UserId == user.Id);
                if(role == null)
                {
                    user.Role = "None";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(u=> u.Id == role.RoleId).Name;
                }
            }
            return View(userlist);
        }

        [HttpGet]
        public IActionResult Edit(string userId)
        {
            var objFromDb = _db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if(objFromDb == null)
            {
                return NotFound();
            }
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            var role = userRole.FirstOrDefault(u=>u.UserId == userId);
            if(role != null)
            {
                objFromDb.RoleId = roles.FirstOrDefault(u => u.Id == role.RoleId).Id;
            }
            objFromDb.RoleList = _db.Roles.Select(u=> new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = u.Name,
                Value = u.Id
            });
            return View(objFromDb);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(ApplicationUser user)
        {
            if(ModelState.IsValid)
            {
                var objFromDb = _db.ApplicationUser.FirstOrDefault(u => u.Id == user.Id);
                if (objFromDb.Email != user.Email)
                {
                    var userWithChosenEmail = _db.Users.FirstOrDefault(u => u.Email == user.Email);
                    if(userWithChosenEmail != null && userWithChosenEmail.Id != objFromDb.Id || user.Email == null)
                    {
                        TempData[SD.Error] = "Chosen email is already in use.";
                        user.RoleList = _db.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
                        {
                            Text = u.Name,
                            Value = u.Id
                        });
                        return View(user);
                    }
                    
                }
                    
                    if (objFromDb == null)
                    {
                        return NotFound();
                    }
                    var userRole = _db.UserRoles.FirstOrDefault(u => u.UserId == objFromDb.Id);
                    if (userRole != null)
                    {
                        var previousName = _db.Roles.Where(u => u.Id == userRole.RoleId).Select(e => e.Name).FirstOrDefault();
                        await _usermanager.RemoveFromRoleAsync(objFromDb, previousName);
                    }

                    await _usermanager.AddToRoleAsync(objFromDb, _db.Roles.FirstOrDefault(u => u.Id == user.RoleId).Name);
                    objFromDb.Name = user.Name;
                    objFromDb.Email = user.Email;
                objFromDb.EmailConfirmed = false;
                    _db.SaveChanges();
                TempData[SD.Success] = "User updated!";
                return RedirectToAction(nameof(Index));

                
            }
            TempData[SD.Error] = "Something went wrong.";
            user.RoleList = _db.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = u.Name,
                Value = u.Id
            });
            return View(user);
        }

        [HttpPost]
        public IActionResult LockUnlock(string userId)
        {
            var objFromDb = _db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (objFromDb == null)
            {
                return NotFound();
            }
            if(objFromDb.LockoutEnd!=null && objFromDb.LockoutEnd > DateTime.Now)
            {
                //unlock
                objFromDb.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "User unlocked!";
            }
            else
            {
                //user not locked, locking him
                objFromDb.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData[SD.Success] = "User locked!";
            }
            _db.SaveChanges();
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        public IActionResult Delete(string userId)
        {
            var user = _db.ApplicationUser.FirstOrDefault(u=>u.Id == userId);
            if(user == null)
            {
                return NotFound();
            }
            _db.ApplicationUser.Remove(user);
            _db.SaveChanges();
            TempData[SD.Success] = "User deleted!";
            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> ManageUserClaims(string userId)
        {
            var user = await _usermanager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            var existingUserClaims = await _usermanager.GetClaimsAsync(user);

            var model = new UserClaimsVM()
            {
                UserId = userId
            };

            foreach(Claim claim in ClaimStore.claimsList)
            {
                UserClaim userClaim = new UserClaim()
                {
                    ClaimType = claim.Type
                };
                if(existingUserClaims.Any(c=>c.Type == claim.Type))
                {
                    userClaim.IsSelected = true;
                }
                model.userClaims.Add(userClaim);
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaims(UserClaimsVM userClaimsVM)
        {
            var user = await _usermanager.FindByIdAsync(userClaimsVM.UserId);
            if (user == null)
            {
                return NotFound();
            }

            var claims = await _usermanager.GetClaimsAsync(user);
            var result = await _usermanager.RemoveClaimsAsync(user,claims);

            if(!result.Succeeded)
            {
                TempData[SD.Error] = "Error while updating claims.";
                return View(userClaimsVM);

            }

            result = await _usermanager.AddClaimsAsync(user, userClaimsVM.userClaims.
                Where(c => c.IsSelected == true).
                Select(c => new Claim(c.ClaimType, c.IsSelected.ToString())));

            if(!result.Succeeded)
            {
                TempData[SD.Error] = "Error while updating claims.";
                return View(userClaimsVM);
            }

            TempData[SD.Success] = "Claims updated successfully.";
            return RedirectToAction(nameof(Index));
        }
    }
}
