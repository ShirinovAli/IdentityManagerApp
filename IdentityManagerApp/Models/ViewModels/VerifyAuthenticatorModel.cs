using System.ComponentModel.DataAnnotations;

namespace IdentityManagerApp.Models.ViewModels
{
    public class VerifyAuthenticatorModel
    {
        [Required]
        public string Code { get; set; }
        public string ReturnUrl { get; set; }
        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }
}
