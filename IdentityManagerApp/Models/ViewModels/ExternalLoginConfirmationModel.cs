using System.ComponentModel.DataAnnotations;

namespace IdentityManagerApp.Models.ViewModels
{
    public class ExternalLoginConfirmationModel
    {
        [Required]
        public string Name { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
