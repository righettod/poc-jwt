package eu.righettod.pocjwt.constant;

import java.io.File;

/**
 * Project constants
 */
public class Constants {

    public final static String JDBC_URL = "jdbc:h2:file:" + new File("target/store").getAbsolutePath() + ";INIT=RUNSCRIPT FROM 'classpath:db_creation.sql';DB_CLOSE_ON_EXIT=TRUE;";
}
