package de.mobe.hacman;

import java.text.MessageFormat;
import java.util.Optional;

public class Main {

    private static final int OK = 0;

    public static void main(String... args) {
        HacMan hacman = new HacMan();
        Optional<String> result = hacman.run(args);

        String msg = MessageFormat.format("<script-result>{0}</script-result>",
                                          result.orElse(HacMan.VOID_SCRIPT_RESULT));

        System.out.println(msg);// NOSONAR

        System.exit(OK);
    }
}
