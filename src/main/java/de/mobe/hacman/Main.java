package de.mobe.hacman;

import java.text.MessageFormat;
import java.util.Optional;

public class Main {

    public static final int OK = 0;
    public static final int ERR = 1;
    public static final String HAC_MAN_ERROR = "HacMan: Error";

    public static void main(String... args) {
        HacMan hacman = new HacMan();
        Optional<String> result = hacman.run(args);

        String hacManResult =
            MessageFormat.format("<hacman>{0}{1}{2}</hacman>",
                                 System.lineSeparator(),
                                 result.orElse("HacMan Error. See log file."),
                                 System.lineSeparator());

        System.out.println(hacManResult);// NOSONAR

        if (hacManResult.contains(HAC_MAN_ERROR)) {
            System.exit(ERR);
        }

        System.exit(OK);
    }
}
