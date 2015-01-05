import java.awt.image.*;
import java.io.*;
import javax.imageio.*;

import nl.captcha.Captcha;
import nl.captcha.text.producer.TextProducer;
import nl.captcha.gimpy.DropShadowGimpyRenderer;
import nl.captcha.gimpy.FishEyeGimpyRenderer;
import nl.captcha.backgrounds.GradiatedBackgroundProducer;

public class CTool {

    public static final String[] urls =  {
        "http://yhoo.it/tY2uPT",
        "http://yhoo.it/rNh5C6",
        "http://yhoo.it/uUMWem",
        "http://yhoo.it/sVzLJi",
        "http://yhoo.it/rYwYRt",
        "http://yhoo.it/tazMYM",
        "http://yhoo.it/tnzj4I",
        "http://yhoo.it/rC1oyY",
        "http://yhoo.it/sulWbe",
        "http://yhoo.it/vEncub"
    };

    public static final String[] files = {
        "pings/primasowing01.png",
        "pings/primasowing02.png",
        "pings/primasowing03.png",
        "pings/primasowing04.png",
        "pings/primasowing05.png",
        "pings/primasowing06.png",
        "pings/primasowing07.png",
        "pings/primasowing08.png",
        "pings/primasowing09.png",
        "pings/primasowing10.png"
    };

    public static int counter = 0;


    public static void main(String[] args){
        TextProducer textProducer = new TextProducer(){
                public String getText(){ return  urls[counter++]; }
            };

        System.err.println("Starting");
        for(int i = 0; i < urls.length; i++){
            Captcha.Builder builder = new Captcha.Builder(500, 100);
            builder.addBackground(new GradiatedBackgroundProducer());
            builder.addText(textProducer);
            builder.addNoise();
            builder.gimp(new DropShadowGimpyRenderer());
            builder.gimp(new FishEyeGimpyRenderer());
            builder.addBorder();
            Captcha captcha = builder.build();
            export(captcha, files[i]);
        }
            System.err.println("Stopping");
    }


    public static boolean export(Captcha captcha, String path){
        try {
            BufferedImage image = captcha.getImage();
            File file = new File(path);
            ImageIO.write(image, "png", file);
        } catch (IOException e) {
            System.err.println("Exporting threw " + e);
            return false;
        } 
        return true;
    }
    

}


