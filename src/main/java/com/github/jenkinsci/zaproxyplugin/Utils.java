package com.github.jenkinsci.zaproxyplugin;

import java.text.MessageFormat;

import hudson.model.BuildListener;

/**
 * @author Ludovic Roucoux
 * @author Johann Ollivier-Lapeyre
 * @author Thilina Madhusanka
 * @author Abdellah Azougarh
 * @author Goran Sarenkapa
 * @author Mostafa AbdelMoez
 * @author Tanguy de Lignières
 */
public class Utils {
    public static final String ZAP = "ZAP Jenkins Plugin";
    public static final String ZAP_DRIVER = "ZAPDriver";
    public static final String ZAP_BUILDER = "ZAPBuilder";
    public static final String ZAP_ERROR = ":ERROR";
    public static final String ZAP_WARNING = ":WARNING";
    public static final String ZAP_NOTICE = ":NOTICE";
    public static final String ZAP_SUCCESS = ":SUCCESS";
    /**
     * Message builder method that accepts a list of arguments. Used for internationalized messages.
     *
     * @param listener
     *            of TYPE BuildListener DESC: the listener to display log during the job execution in Jenkin
     * @param message
     *            of TYPE String DESC: The message to display in the log, injected values are indicated by {0}, {1}, etc.
     * @param args
     *            of TYPE String... DESC: The injected values to go into the message.
     */
    
    public static void lineBreak(BuildListener listener) {
        String message = "";
        MessageFormat mf = new MessageFormat(message);
        listener.getLogger().println(mf.format(null));
    }

    public static void loggerMessage(BuildListener listener, int indent, String message, String... args) {
        MessageFormat mf = new MessageFormat(indent(message, indent));
        listener.getLogger().println(mf.format(args));
    }

    public static String indent(String str, int indent) {
        String temp = "";
        for (int i = 0; i < indent; i++)
            temp = temp + "\t";
        return temp + str;
    }
}
