﻿using Identity_Training_App.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity_Training_App.Controllers
{

    public class RolesController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _usermanager;
        private readonly RoleManager<IdentityRole> _rolemanager;

        public RolesController(ApplicationDbContext db, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> rolemanager)
        {
            _db = db;
            _usermanager = userManager;
            _rolemanager = rolemanager;
        }
        public IActionResult Index()
        {
            var roles = _db.Roles.ToList();
            return View(roles);
        }

        [HttpGet]
        public IActionResult Upsert(string id)
        {
            if(String.IsNullOrEmpty(id))
            {
                return View();
            }
            else
            {
                //update
                var obj = _db.Roles.FirstOrDefault(u=>u.Id == id);
                return View(obj);
            }
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole roleObj)
        {
            if(await _rolemanager.RoleExistsAsync(roleObj.Name))
            {
                TempData[SD.Error] = "Role alredy exists.";
                return RedirectToAction(nameof(Index));
            }
            if(string.IsNullOrEmpty(roleObj.Id))
            {
                await _rolemanager.CreateAsync(new IdentityRole { Name = roleObj.Name});
                TempData[SD.Success] = "Role created!.";
            }
            else
            {

                var objRoleFromDb = _db.Roles.FirstOrDefault(u=>u.Id == roleObj.Id);
                if(objRoleFromDb == null)
                {
                    TempData[SD.Error] = "Role not found.";
                    return RedirectToAction(nameof(Index));
                }
                objRoleFromDb.Name = roleObj.Name;
                objRoleFromDb.NormalizedName = roleObj.Name.ToUpper();
                var result = await _rolemanager.UpdateAsync(objRoleFromDb);
                TempData[SD.Success] = "Role updated!";
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            var roleToDelete = _db.Roles.FirstOrDefault(u=>u.Id==id);
            if(roleToDelete == null)
            {
                TempData[SD.Error] = "Role not found.";
                return RedirectToAction(nameof(Index));
            }
            var userRolesForThisRole = _db.UserRoles.Where(u => u.RoleId == id).Count();
            if(userRolesForThisRole>0)
            {
                TempData[SD.Error] = "Cannot delete this role, since there are users assigned to this role.";
                return RedirectToAction(nameof(Index));
            }
            await _rolemanager.DeleteAsync(roleToDelete);
            TempData[SD.Success] = "Deleted successfully.";
            return RedirectToAction(nameof(Index));
        }
    }
}
