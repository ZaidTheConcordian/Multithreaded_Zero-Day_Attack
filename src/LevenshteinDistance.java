/*
 * The Levenshtein distance is a number that tells you how different two strings are. The higher the number, the more different the two strings are.
 * For more information: https://en.wikipedia.org/wiki/Levenshtein_distance
 */

public class LevenshteinDistance {

    public double Change_Ratio = 0.0;           // attribute used to measure the change percentage.
    public boolean acceptable_change = false;   // attribute used to measure acceptable change.

    // Function used to get the minimum change role based on the Levenshtein Distance algorithm.
    private int min(int i, int i1, int i2)
    {
        return Math.min(i, Math.min(i1, i2));
    }

    // Function to calculate the change ratio between two strings.
    private void Measure_Change_Ratio(int i, int length) {
        // the variable i is the number of changes / total length of string.
        this.Change_Ratio = 1- Double.valueOf(i)/Double.valueOf(length);
        // if the change ratio is greater than 5% (assignment requirements),
        // then it is acceptable change to increment the number of Vulnerabilities.
        this.acceptable_change = (this.Change_Ratio > 0.05)? true: false;
    }

    // If the characters are not equal, then the cost of distance by one.
    public int SubstitutionCost(char a, char b)
    {
        return (a == b) ? 0 : 1;
    }

    // The main function to run the Levenshtein Distance algorithm
    public int Calculate(String str1, String str2)
    {
        int[][] dp = new int[str1.length() + 1][str1.length() + 1];

        for (int i = 0; i <= str1.length(); i++) {
            for (int j = 0; j <= str2.length(); j++) {
                if (i == 0) {
                    // Initial first rows from 0 to N, where N is the length of string.
                    dp[i][j] = j;
                }
                else if (j == 0) {
                    // Initial first columns from 0 to N, where N is the length of string.
                    dp[i][j] = i;
                }
                else {
                    // If the row and column are not the first, then do measure.
                    dp[i][j] = min(dp[i - 1][j - 1]
                                    + SubstitutionCost(str1.charAt(i - 1), str2.charAt(j - 1)),
                            dp[i - 1][j] + 1,
                            dp[i][j - 1] + 1);
                }
            }
        }
        // The ratio is the number of changes / length of str1, where str1 is the vulnerability pattern.
        Measure_Change_Ratio(dp[str1.length()][str2.length()], str1.length());
        // return the total the number of changes
        return dp[str1.length()][str2.length()];
    }

    // Function to return the boolean value that used to update number of children on the master thread.
    public boolean isAcceptable_change()
    {
        return this.acceptable_change;
    }
}