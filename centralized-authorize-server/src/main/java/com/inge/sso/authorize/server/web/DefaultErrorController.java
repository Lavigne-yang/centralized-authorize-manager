package com.inge.sso.authorize.server.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;

/**
 * @author lavyoung1325
 */
@Controller
public class DefaultErrorController implements ErrorController {


    private static final Logger logger = LoggerFactory.getLogger(DefaultErrorController.class);

    @RequestMapping("/error")
    public String handleError(Model model, HttpServletRequest request) {
        String errorMessage = getErrorMessage(request);
        logger.info("authorization error message :{}", errorMessage);
        if (errorMessage.startsWith("[access_denied]")) {
            model.addAttribute("errorTitle", "Access Denied");
            model.addAttribute("errorMessage", "You have denied access.");
        } else {
            model.addAttribute("errorTitle", "Error");
            model.addAttribute("errorMessage", errorMessage);
        }
        return "error";
    }

    private String getErrorMessage(HttpServletRequest request) {
        String errorMessage = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
        return StringUtils.hasText(errorMessage) ? errorMessage : "";
    }

}