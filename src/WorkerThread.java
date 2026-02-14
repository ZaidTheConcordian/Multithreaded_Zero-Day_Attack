// work thread
public class WorkerThread implements Runnable {
    private String logLine;
    private String vulnerabilityPattern;
    private MasterThread masterThread;
    private int lineIndex;

    public WorkerThread(String logLine, String vulnerabilityPattern,
                        MasterThread masterThread, int lineIndex) {
        this.logLine = logLine;
        this.vulnerabilityPattern = vulnerabilityPattern;
        this.masterThread = masterThread;
        this.lineIndex = lineIndex;
    }

    @Override
    public void run() {

        String logStatement = extractLogStatement(logLine);
        boolean vulnerabilityFound = searchVulnerability(logStatement);

        if (vulnerabilityFound) {
            masterThread.incrementCount();
            System.out.println("Worker Thread: the " + lineIndex +
                               " VULNERABILITY FOUND");
        }
    }

    private String extractLogStatement(String fullLogLine) {

        int logIndex = fullLogLine.indexOf("Log:");
        if (logIndex != -1) {

            return fullLogLine.substring(logIndex + 4).trim();
        } else {

            return fullLogLine.trim();
        }
    }


    private boolean searchVulnerability(String logStatement) {
        int patternLength = vulnerabilityPattern.length();

        if (logStatement.length() < patternLength) {
            return false;
        }

        LevenshteinDistance levenshtein = new LevenshteinDistance();


        for (int i = 0; i <= logStatement.length() - patternLength; i++) {

            String substring = logStatement.substring(i, i + patternLength);

            int distance = levenshtein.Calculate(vulnerabilityPattern, substring);

            if (levenshtein.isAcceptable_change()) {

                return true;
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        return false;
    }

    public String getLogLine() {
        return logLine;
    }

    public int getLineIndex() {
        return lineIndex;
    }
}