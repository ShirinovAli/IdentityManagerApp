using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace IdentityManagerApp.Models
{
    public class AppUser : IdentityUser
    {
        [Required]
        public string Name { get; set; }

    }
}
