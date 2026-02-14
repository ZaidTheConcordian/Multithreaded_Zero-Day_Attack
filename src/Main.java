import java.io.IOException;

public class Main {
    public static void main(String[] args) {
        // Path to the dataset file you uploaded (e.g. vm 1.txt inside DataSet/)
        String datasetPath = "DataSet/vm_1.txt";   // adjust if the file lives elsewhere

        try {
            MasterThread master = new MasterThread(datasetPath);
            Thread masterThread = new Thread(master, "MasterThread");
            masterThread.start();

            // Optionally join to wait for completion before exiting the JVM
            masterThread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}