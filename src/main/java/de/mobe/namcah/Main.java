package de.mobe.namcah;

import java.text.MessageFormat;
import java.util.Optional;

public class Main {

    public static final int OK = 0;
    public static final int ERR = 1;
    public static final String HAC_MAN_ERROR = "Namcah: Error";

    public static void main(String... args) {

        Optional<String> result = (new Namcah()).runHac(args);

        String hacManResult =
            MessageFormat.format("{0}",
                                 result.orElse("Namcah Error. Check out the namcah log file."));

        System.out.println(hacManResult);// NOSONAR

        if (hacManResult.contains(HAC_MAN_ERROR)) {
            System.exit(ERR);
        }

        System.exit(OK);
    }
}
