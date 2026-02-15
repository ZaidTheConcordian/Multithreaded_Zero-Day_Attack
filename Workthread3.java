public class WorkerThread implements Runnable {

    // Inputs + shared coordinator
    private final String logLine;
    private final String vulnerabilityPattern;
    private final MasterThread masterThread;
    private final int lineIndex;

    // Store inputs for this worker
    public WorkerThread(String logLine, String vulnerabilityPattern,
                        MasterThread masterThread, int lineIndex) {
        this.logLine = logLine;
        this.vulnerabilityPattern = vulnerabilityPattern;
        this.masterThread = masterThread;
        this.lineIndex = lineIndex;
    }

    @Override
    public void run() {
        // 1) Extract message, 2) scan, 3) report if found
        String logStatement = extractLogStatement(logLine);
        boolean vulnerabilityFound = searchVulnerability(logStatement);

        if (vulnerabilityFound) {
            masterThread.incrementCount();
            System.out.println("Worker Thread: line " + lineIndex +
                    " found Vulnerability in log: " +
                    logStatement.substring(0, Math.min(30, logStatement.length())) + "...");
        }
    }

    private String extractLogStatement(String fullLogLine) {
        // Return text after "Log:" if present, else the whole trimmed line
        if (fullLogLine == null) return "";

        int logIndex = fullLogLine.indexOf("Log:");
        if (logIndex != -1) {
            return fullLogLine.substring(logIndex + 4).trim();
        }
        return fullLogLine.trim();
    }

    private boolean searchVulnerability(String logStatement) {
        // Sliding-window approximate match using Levenshtein similarity
        if (logStatement == null) return false;
        if (vulnerabilityPattern == null || vulnerabilityPattern.isEmpty()) return false;

        int patternLength = vulnerabilityPattern.length();
        if (logStatement.length() < patternLength) return false;

        LevenshteinDistance levenshtein = new LevenshteinDistance();

        for (int i = 0; i <= logStatement.length() - patternLength; i++) {
            String substring = logStatement.substring(i, i + patternLength);
            int distance = levenshtein.Calculate(vulnerabilityPattern, substring);
            double ratio = 1.0 - (double) distance / patternLength;

            if (ratio >= 0.95) {
                return true;
            }

            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }

        return false;
    }

    public String getLogLine() {
        // For debugging/tests
        return logLine;
    }

    public int getLineIndex() {
        // For debugging/tests
        return lineIndex;
    }
}
