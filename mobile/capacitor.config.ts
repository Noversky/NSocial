import type { CapacitorConfig } from "@capacitor/cli";

const config: CapacitorConfig = {
  appId: "com.nsocial.app",
  appName: "NSocial",
  webDir: "www",
  server: {
    url: "https://nsocial.onrender.com/",
    cleartext: false
  },
  plugins: {
    SplashScreen: {
      launchShowDuration: 1500,
      backgroundColor: "#0b1020",
      androidScaleType: "CENTER_CROP",
      showSpinner: false
    }
  }
};

export default config;
