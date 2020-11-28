
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NETCore.MailKit.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityExample.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailService _emailService;

        public HomeController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IEmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
        } 
        public IActionResult Index()
        {
            return View();
        }
        
        [Authorize] //here we ask "Are u allowed to come here?"
        public IActionResult Secret()
        {
            return View();
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            var user = await _userManager.FindByNameAsync(username);

            if(user!=null)
            {
                var signResult = await _signInManager.PasswordSignInAsync(user, password, false, true);

                if(signResult.Succeeded)
                {
                    return RedirectToAction("Index");
                }
            }

            return RedirectToAction("Erorr");

        }
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(string username, string password)
        {
            var user = new IdentityUser
            {
                UserName = username,
            };
            
            var result = await _userManager.CreateAsync(user, password);

            if(result.Succeeded)
            {
                //generate tocken
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                
                var link = Url.Action(nameof(VerifyEmail), "Home", new { userId = user.Id, code }, Request.Scheme, Request.Host.ToString());

                await _emailService.SendAsync("rosiervstutiel@gmail.com", "email verify", $"<a href=\"{link}\">Verify Email</a>", true);

                return RedirectToAction("Index");
            }

            return RedirectToAction("Error");
        }

        public async Task<IActionResult> LogOut()
        {
            await _signInManager.SignOutAsync();            
            return RedirectToAction("Index");
        }

        public IActionResult Error()
        {
            return View();
        }

        public async Task<IActionResult> VerifyEmail(string userId, string code)
        {
            var result = await _userManager.ConfirmEmailAsync(await _userManager.FindByIdAsync(userId), code);

            if (result.Succeeded)
            {
                return View();
            }

            return RedirectToAction("Erro r");
        }
        public IActionResult EmailVerification() => View();

        //public IActionResult Authenticate()
        //{
        //Checking Claims way to Auth & how it is Routing, which middlewares should be under anothers 
        //var maryClaims = new List<Claim>()
        //{
        //    new Claim(ClaimTypes.Name, "Marta"),
        //    new Claim(ClaimTypes.Email, "marta@gmail.com"),
        //    new Claim(ClaimTypes.Role, "user")
        //};

        //var maryIdentity = new ClaimsIdentity(maryClaims, "Mary Identity");

        //var userPrincipal = new ClaimsPrincipal(new[] { maryIdentity });

        //HttpContext.SignInAsync(userPrincipal);
    //        return RedirectToAction("Index");
    //}
}
}
