import java.awt.image.*;
import java.io.*;
import javax.imageio.*;
import java.util.*;
import java.awt.*;

import nl.captcha.Captcha;
import nl.captcha.text.producer.TextProducer;
import nl.captcha.text.renderer.DefaultWordRenderer;
import nl.captcha.gimpy.DropShadowGimpyRenderer;
import nl.captcha.gimpy.FishEyeGimpyRenderer;
import nl.captcha.backgrounds.GradiatedBackgroundProducer;

public class Pinger {
    static  boolean verbose = false; 


    static final java.util.List<java.awt.Color> textColors = 
        Arrays.asList(Color.YELLOW, Color.CYAN, Color.BLUE, Color.MAGENTA,  Color.GREEN, Color.ORANGE, Color.PINK, Color.RED);
    static final java.util.List<java.awt.Font> textFonts = 
        Arrays.asList(new Font("Arial", Font.BOLD, 40), new Font("Courier", Font.BOLD, 40));


    public static void main(String[] args){
        if(verbose){ System.err.println("Pinger: " + args.length); }
        if(args.length != 3){ 
            return; 
        } else {
            verbose = Boolean.valueOf(args[0]);
            final String password = args[1];
            final String filename = args[2];
            TextProducer textProducer = new TextProducer(){
                    public String getText(){ return  password; }
                };
            
            if(verbose){ System.err.println("Starting"); }
            Captcha.Builder builder = new Captcha.Builder(500, 100);
            builder.addBackground(new GradiatedBackgroundProducer());
            builder.addText(textProducer, new DefaultWordRenderer(textColors, textFonts));
            builder.addNoise();
            builder.gimp(new DropShadowGimpyRenderer());
            builder.gimp(new FishEyeGimpyRenderer());
            builder.addBorder();
            Captcha captcha = builder.build();
            export(captcha, filename);  
            if(verbose){ System.err.println("Stopping"); }
        }
    }

    
    public static boolean export(Captcha captcha, String path){
        try {
            BufferedImage image = captcha.getImage();
            File file = new File(path);
            ImageIO.write(image, "png", file);
        } catch (IOException e) {
            if(verbose){ System.err.println("Exporting threw " + e); }
            return false;
        } 
        return true;
    }
    
    
}


