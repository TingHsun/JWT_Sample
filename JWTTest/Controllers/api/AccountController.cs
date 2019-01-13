using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using JWTTest.Extensions;
using JWTTest.Data;
using Newtonsoft.Json;

namespace JWTTest.Controllers.api
{
    [Produces("application/json")]
    [Route("api/Account")]
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _dbContext;

        public AccountController(ApplicationDbContext db)
        {
            this._dbContext = db;
        }

        [Authorize]
        [HttpGet]
        public IActionResult get()
        {

            var obj2 = this.GetDbUser(_dbContext);

            return Content(JsonConvert.SerializeObject(new { _data = obj2 }, Formatting.Indented), "application/json");
        }
        

    }
}