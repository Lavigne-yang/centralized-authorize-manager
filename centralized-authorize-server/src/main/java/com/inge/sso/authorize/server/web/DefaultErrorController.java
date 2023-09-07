package com.inge.sso.authorize.server.web;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

/**
 * @author lavyoung1325
 */
@Controller
public class DefaultErrorController implements ErrorController {


    private static final Logger logger = LoggerFactory.getLogger(DefaultErrorController.class);

    @RequestMapping("/error")
    public String handleError(Model model, HttpServletRequest request, HttpServletResponse response) {
        String errorMessage = getErrorMessage(request, response);
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

    private String getErrorMessage(HttpServletRequest request, HttpServletResponse response) {
        List<String> errMessage = new ArrayList<>();
        errMessage.add(request.getUserPrincipal().getName());
        errMessage.add(String.valueOf(response.getStatus()));
        errMessage.add((String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE));
        return StringUtils.join(errMessage, " ");
    }

}