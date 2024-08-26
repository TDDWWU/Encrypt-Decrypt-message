//import java.io.BufferedReader;
//import java.io.FileReader;
//import java.io.IOException;
//import java.util.Collections;
//import java.util.HashSet;
//import java.util.Set;
//import java.util.concurrent.ConcurrentHashMap;
//
//class MemberList {
//    private static final Set<String> notMemberList = ConcurrentHashMap.newKeySet();
//    private static final String Member_FILE = "Member.txt";
//    private static final long UPDATE_INTERVAL = 1; // renew time
//
//    static void startUpdating() {
//        new Thread(() -> {
//            while (!Thread.interrupted()) {
//                update();
//                try {
//                    Thread.sleep(UPDATE_INTERVAL);
//                } catch (InterruptedException e) {
//                    Thread.currentThread().interrupt();
//                }
//            }
//        }).start();
//    }
//
//    private static void update() {
//        Set<String> newBlockedUrls = new HashSet<>();
//        try (BufferedReader reader = new BufferedReader(new FileReader(Member_FILE))) {
//            String line;
//            while ((line = reader.readLine()) != null) {
//                // Split the line by '|' and trim each ID
//                String[] ID_List = line.split("\\|");
//                for (String ID : ID_List) {
//                    newBlockedUrls.add(ID.trim()); // Remove any leading and trailing spaces
//                }
//            }
//
//        } catch (IOException e) {
//            System.err.println("Error reading blocked URLs: " + e.getMessage());
//        }
//        notMemberList.clear();
//        notMemberList.addAll(newBlockedUrls);
//    }
//
//    static boolean isMember(String ID) {
//        return notMemberList.stream().anyMatch(ID::contains);
//    }
//
//    static Set<String> getMemberList() {
//        return Collections.unmodifiableSet(notMemberList);
//    }
//
//
//}