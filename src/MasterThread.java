import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class MasterThread implements Runnable {

    /* ---------- configuration ---------- */
    private static final String VULNERABILITY_PATTERN = "V04K4B63CL5BK0B";
    private static final long Sleep_timer = 2_000L;   //Sleep for 2 seconds

    /* ---------- state ---------- */
    private final String[] logLines;          // all lines from the dataset file
    private volatile int count = 0;           // total vulnerabilities found
    private int workerNumber = 2;             // start with 2 workers
    private double avg = 0.0;                 // previous average (Count / processed)
    private final Object lock = new Object(); // protects `count`

    public MasterThread(String datasetPath) throws IOException {
        Path p = Paths.get(datasetPath);
        List<String> lines = Files.readAllLines(p); // read all lines into a List
        this.logLines = lines.toArray(new String[0]);// convert List to array for faster access
    }
    // Method to safely increment the count of vulnerabilities found
    public void incrementCount() {
        synchronized (lock) { // ensure that only one thread updates `count` at a time
            count++;
        }
    }

    @Override
    public void run() {
        int processedLines = 0;                     // how many lines have been handed out
        int totalLines = logLines.length;

        while (processedLines < totalLines) {
            try {
                Thread.sleep(Sleep_timer); // Sleep
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            System.out.print(processedLines+"\n");


            List<Thread> currentBatch = new ArrayList<>(); // keep track of the threads we just launched

            for (int i = 0;
                 i < workerNumber && processedLines < totalLines; //Should be or here -----------------------
                 i++, processedLines++) {

                String line = logLines[processedLines];
                WorkerThread worker = new WorkerThread(
                        line,
                        VULNERABILITY_PATTERN,
                        this,
                        processedLines);               // give each worker its line index

                Thread t = new Thread(worker,
                        "Worker-" + i);      // give the thread a readable name
                currentBatch.add(t);

                t.start();

            }

            // Wait for all threads in the current batch to finish before checking results and potentially scaling up
            for (Thread t : currentBatch) {

                try {
                    t.join();                             // blocks until this worker ends
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    System.err.println("Master interrupted while joining workers.");
                    return;                               // abort the whole run
                }
            }

            // After all workers in the batch have finished, we can check the results and decide if we need to scale up.
            double approximateAvg = (double) count / totalLines; //  (Count / number of lines in the file)

            // Compare the new average with the previous one to decide if we need to scale up
            if (Math.abs(approximateAvg - avg) >= 0.2 * avg) { //if the change is bigger than 20% of the previous average
                System.out.println("\n=== Scaling up workers ===");
                System.out.printf("Previous avg = %.4f, New avg = %.4f%n", avg, approximateAvg);


                avg = approximateAvg;
                workerNumber += 2;                     // increase pool size for next iteration
            } else {
                // No scaling – just update the stored average
                System.out.println("\n=== No scaling ===");
                System.out.printf("Previous avg = %.4f, New avg = %.4f%n", avg, approximateAvg);

            }
        }

       // After processing all lines, print the final results
        System.out.println("\n=== Run finished ===");
        System.out.println("Total lines processed       : " + processedLines);
        System.out.println("Detected vulnerabilities   : " + count);
        System.out.println("Final worker pool size      : " + workerNumber);
    }
}