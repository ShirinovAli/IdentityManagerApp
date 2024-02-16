using System.ComponentModel.DataAnnotations;

namespace IdentityManagerApp.Models.ViewModels
{
    public class ForgotPasswordModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
