package org.example;

public class Main{
    public static void main(String[] args) {
        TgAuth tgAuth = new TgAuth("7353557403", "e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d");

        boolean res = tgAuth.validateTgAuth("user=%7B%22id%22%3A1797689334%2C%22first_name%22%3A%220xSu%22%2C%22last_name%22%3A%22%22%2C%22username%22%3A%22ecrecover%22%2C%22language_code%22%3A%22en%22%2C%22is_premium%22%3Atrue%2C%22allows_write_to_pm%22%3Atrue%2C%22photo_url%22%3A%22https%3A%5C%2F%5C%2Ft.me%5C%2Fi%5C%2Fuserpic%5C%2F320%5C%2FL23dhoijKxN4unWvLNlHH6b10DX_SnkP5HJAkD7YFmY.svg%22%7D&chat_instance=-9136130925810537568&chat_type=sender&start_param=VcRcYUaetzymhxG4XAMuWp56wLcr9yCsB3nQy2vnNG9dDkwyTSy9e1EE2AkZav5E5SMSaJkC1fu4cPvL92WtjNsTCvEm3vY31ZiATz3JecEr8uRD67WzQR4DNuQ55YQ&auth_date=1740484711&signature=ZlNcsVgzNO9CtFovDRAmWH5SErSONYf0xquUTxJdjhOj6uNOFwyoAltrgGLSuNrvyEQAohk8tHSfcst3zboSCQ&hash=712a82bc7bf7d5914bb3a27dfcfa42ee69ce0b33d1423a0dd5f47e59c10773a4");

        if(res){
            System.out.println("It worked!");
        }
        System.out.println("Hello");
    }
}