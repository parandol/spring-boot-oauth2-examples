package kr.ejsoft.oauth2.client.web;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import kr.ejsoft.oauth2.client.model.User;

@Controller
public class HomeController {
	private static final Logger logger = LoggerFactory.getLogger(HomeController.class);


	@RequestMapping(value="/", method=RequestMethod.GET)
	public ModelAndView home(HttpServletRequest request) {
		logger.debug("Home : /");
		
		User user = (User) request.getSession().getAttribute("user");
		if(user != null) {
			return new ModelAndView("redirect:/account");
		}
		
		ModelAndView mav = new ModelAndView();
		mav.setViewName("index");
		return mav;
	}
	
	@RequestMapping(value="/account", method=RequestMethod.GET)
	public ModelAndView account(HttpServletRequest request) {
		User user = (User) request.getSession().getAttribute("user");
		
		logger.debug("Account : {}", user);
		
		if(user == null) {
			return new ModelAndView("redirect:/");
		}
		
		ModelAndView mav = new ModelAndView();
		mav.addObject("user", user);
		mav.setViewName("account");

		return mav;
	}
}
