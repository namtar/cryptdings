package de.catcode.cryptdings;

import java.nio.charset.Charset;

public class Main {

    public static void main(String[] args) {
        new Main();
    }

    public Main() {
        System.out.println(System.getProperty("file.encoding"));
        System.out.println(Charset.defaultCharset());
    }
}
