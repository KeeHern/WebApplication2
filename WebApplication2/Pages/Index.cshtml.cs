using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace WebApplication2.Pages
{

    public class IndexModel : PageModel
    {
        private readonly IHttpContextAccessor _context;
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(IHttpContextAccessor context, ILogger<IndexModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        public void OnGet()
        {
            _logger.LogInformation("test test123");
        }
    }
}
